package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

// decodeBencodeWithPos decodes a bencoded value starting at the given position
// Returns the decoded value and the new position after consuming the value
func decodeBencodeWithPos(bencodedString string, pos int) (interface{}, int, error) {
	if pos >= len(bencodedString) {
		return nil, pos, fmt.Errorf("Unexpected end of input")
	}

	if bencodedString[pos] == 'i' {
		// Integer: i<number>e
		var endIndex int = -1
		for i := pos + 1; i < len(bencodedString); i++ {
			if bencodedString[i] == 'e' {
				endIndex = i
				break
			}
		}
		if endIndex == -1 {
			return nil, pos, fmt.Errorf("Integer not properly terminated with 'e'")
		}

		numberStr := bencodedString[pos+1 : endIndex]
		number, err := strconv.Atoi(numberStr)
		if err != nil {
			return nil, pos, fmt.Errorf("Invalid integer: %v", err)
		}

		return number, endIndex + 1, nil
	} else if bencodedString[pos] == 'l' {
		// List: l<elements>e
		pos++ // skip 'l'
		list := []interface{}{}

		for pos < len(bencodedString) && bencodedString[pos] != 'e' {
			value, newPos, err := decodeBencodeWithPos(bencodedString, pos)
			if err != nil {
				return nil, pos, err
			}
			list = append(list, value)
			pos = newPos
		}

		if pos >= len(bencodedString) {
			return nil, pos, fmt.Errorf("List not properly terminated with 'e'")
		}

		return list, pos + 1, nil // +1 to skip 'e'
	} else if bencodedString[pos] == 'd' {
		// Dictionary: d<key1><value1>...<keyN><valueN>e
		pos++ // skip 'd'
		dict := make(map[string]interface{})

		for pos < len(bencodedString) && bencodedString[pos] != 'e' {
			// Decode key (must be a string)
			key, newPos, err := decodeBencodeWithPos(bencodedString, pos)
			if err != nil {
				return nil, pos, err
			}

			// Verify key is a string
			keyStr, ok := key.(string)
			if !ok {
				return nil, pos, fmt.Errorf("Dictionary key must be a string")
			}

			pos = newPos

			// Decode value
			value, newPos, err := decodeBencodeWithPos(bencodedString, pos)
			if err != nil {
				return nil, pos, err
			}

			dict[keyStr] = value
			pos = newPos
		}

		if pos >= len(bencodedString) {
			return nil, pos, fmt.Errorf("Dictionary not properly terminated with 'e'")
		}

		return dict, pos + 1, nil // +1 to skip 'e'
	} else if unicode.IsDigit(rune(bencodedString[pos])) {
		// String: <length>:<string>
		var firstColonIndex int

		for i := pos; i < len(bencodedString); i++ {
			if bencodedString[i] == ':' {
				firstColonIndex = i
				break
			}
		}

		if firstColonIndex == 0 {
			return nil, pos, fmt.Errorf("String format error: no colon found")
		}

		lengthStr := bencodedString[pos:firstColonIndex]

		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, pos, err
		}

		if firstColonIndex+1+length > len(bencodedString) {
			return nil, pos, fmt.Errorf("String length exceeds remaining input")
		}

		str := bencodedString[firstColonIndex+1 : firstColonIndex+1+length]
		return str, firstColonIndex + 1 + length, nil
	} else {
		return nil, pos, fmt.Errorf("Unsupported bencode type: %c", bencodedString[pos])
	}
}

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
// - i52e -> 52
// - i-52e -> -52
// - l5:helloi52ee -> ["hello", 52]
// - d3:foo3:bar5:helloi52ee -> {"foo":"bar","hello":52}
func decodeBencode(bencodedString string) (interface{}, error) {
	if len(bencodedString) == 0 {
		return "", fmt.Errorf("Empty bencoded string")
	}

	value, pos, err := decodeBencodeWithPos(bencodedString, 0)
	if err != nil {
		return nil, err
	}

	if pos != len(bencodedString) {
		return nil, fmt.Errorf("Unexpected trailing data")
	}

	return value, nil
}

// findInfoDictionaryBytes finds the "info" key in the bencoded dictionary and returns
// the exact bytes of the info dictionary value
func findInfoDictionaryBytes(fileData []byte) ([]byte, error) {
	bencodedString := string(fileData)
	pos := 0

	// Must start with 'd'
	if pos >= len(bencodedString) || bencodedString[pos] != 'd' {
		return nil, fmt.Errorf("Expected dictionary at start")
	}
	pos++ // skip 'd'

	// Parse through dictionary keys to find "info"
	for pos < len(bencodedString) && bencodedString[pos] != 'e' {
		// Decode key
		key, newPos, err := decodeBencodeWithPos(bencodedString, pos)
		if err != nil {
			return nil, err
		}

		keyStr, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("Dictionary key must be a string")
		}

		pos = newPos

		// If this is the "info" key, extract the value bytes
		if keyStr == "info" {
			// The value starts at pos
			valueStart := pos

			// We need to find where this value ends
			// Since it's a dictionary, we need to parse it to find the matching 'e'
			_, valueEnd, err := decodeBencodeWithPos(bencodedString, pos)
			if err != nil {
				return nil, err
			}

			// Extract the bytes (convert back to byte slice indices)
			return fileData[valueStart:valueEnd], nil
		}

		// Skip the value to get to the next key
		_, newPos, err = decodeBencodeWithPos(bencodedString, pos)
		if err != nil {
			return nil, err
		}
		pos = newPos
	}

	return nil, fmt.Errorf("'info' key not found in dictionary")
}

// readPeerMessage reads a peer message from the connection
// Returns message ID and payload
func readPeerMessage(conn net.Conn) (uint8, []byte, error) {
	// Read message length (4 bytes, big-endian)
	lengthBytes := make([]byte, 4)
	totalRead := 0
	for totalRead < 4 {
		n, err := conn.Read(lengthBytes[totalRead:])
		if err != nil {
			return 0, nil, err
		}
		totalRead += n
	}
	messageLength := binary.BigEndian.Uint32(lengthBytes)

	// Keep-alive message (length 0)
	if messageLength == 0 {
		return 0, nil, nil
	}

	// Read message ID (1 byte)
	messageIDBytes := make([]byte, 1)
	_, err := conn.Read(messageIDBytes)
	if err != nil {
		return 0, nil, err
	}
	messageID := messageIDBytes[0]

	// Read payload (messageLength - 1 bytes, since ID is 1 byte)
	payloadLength := int(messageLength) - 1
	if payloadLength < 0 {
		return 0, nil, fmt.Errorf("invalid message length: %d", messageLength)
	}

	payload := make([]byte, payloadLength)
	totalRead = 0
	for totalRead < payloadLength {
		n, err := conn.Read(payload[totalRead:])
		if err != nil {
			return 0, nil, err
		}
		totalRead += n
	}

	return messageID, payload, nil
}

// sendPeerMessage sends a peer message to the connection
func sendPeerMessage(conn net.Conn, messageID uint8, payload []byte) error {
	messageLength := uint32(1 + len(payload)) // 1 byte for ID + payload

	// Write message length (4 bytes, big-endian)
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, messageLength)
	_, err := conn.Write(lengthBytes)
	if err != nil {
		return err
	}

	// Write message ID
	_, err = conn.Write([]byte{messageID})
	if err != nil {
		return err
	}

	// Write payload (if any)
	if len(payload) > 0 {
		_, err = conn.Write(payload)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Fprintln(os.Stderr, "Logs from your program will appear here!")

	command := os.Args[1]

	if command == "decode" {
		// TODO: Uncomment the code below to pass the first stage
		bencodedValue := os.Args[2]

		decoded, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else if command == "info" {
		filename := os.Args[2]

		// Read the torrent file as bytes (it may contain binary data)
		fileData, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		// Convert bytes to string (Go strings can contain arbitrary bytes)
		bencodedString := string(fileData)

		// Decode the bencoded dictionary
		decoded, err := decodeBencode(bencodedString)
		if err != nil {
			fmt.Printf("Error decoding bencode: %v\n", err)
			os.Exit(1)
		}

		// Cast to map[string]interface{}
		torrentDict, ok := decoded.(map[string]interface{})
		if !ok {
			fmt.Println("Error: torrent file does not contain a dictionary")
			os.Exit(1)
		}

		// Extract announce (tracker URL)
		announce, ok := torrentDict["announce"]
		if !ok {
			fmt.Println("Error: torrent file missing 'announce' field")
			os.Exit(1)
		}
		announceStr, ok := announce.(string)
		if !ok {
			fmt.Println("Error: 'announce' field is not a string")
			os.Exit(1)
		}

		// Extract info dictionary
		info, ok := torrentDict["info"]
		if !ok {
			fmt.Println("Error: torrent file missing 'info' field")
			os.Exit(1)
		}
		infoDict, ok := info.(map[string]interface{})
		if !ok {
			fmt.Println("Error: 'info' field is not a dictionary")
			os.Exit(1)
		}

		// Extract length from info
		length, ok := infoDict["length"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'length' field")
			os.Exit(1)
		}
		lengthInt, ok := length.(int)
		if !ok {
			fmt.Println("Error: 'length' field is not an integer")
			os.Exit(1)
		}

		// Extract the info dictionary bytes for hashing
		infoBytes, err := findInfoDictionaryBytes(fileData)
		if err != nil {
			fmt.Printf("Error extracting info dictionary: %v\n", err)
			os.Exit(1)
		}

		// Calculate SHA-1 hash
		hash := sha1.Sum(infoBytes)
		infoHash := fmt.Sprintf("%x", hash)

		// Extract piece length from info
		pieceLength, ok := infoDict["piece length"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'piece length' field")
			os.Exit(1)
		}
		pieceLengthInt, ok := pieceLength.(int)
		if !ok {
			fmt.Println("Error: 'piece length' field is not an integer")
			os.Exit(1)
		}

		// Extract pieces from info
		pieces, ok := infoDict["pieces"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'pieces' field")
			os.Exit(1)
		}
		piecesStr, ok := pieces.(string)
		if !ok {
			fmt.Println("Error: 'pieces' field is not a string")
			os.Exit(1)
		}

		// Convert pieces string to bytes and split into 20-byte chunks
		piecesBytes := []byte(piecesStr)
		if len(piecesBytes)%20 != 0 {
			fmt.Printf("Error: 'pieces' length (%d) is not a multiple of 20\n", len(piecesBytes))
			os.Exit(1)
		}

		// Print the information
		fmt.Printf("Tracker URL: %s\n", announceStr)
		fmt.Printf("Length: %d\n", lengthInt)
		fmt.Printf("Info Hash: %s\n", infoHash)
		fmt.Printf("Piece Length: %d\n", pieceLengthInt)
		fmt.Println("Piece Hashes:")
		for i := 0; i < len(piecesBytes); i += 20 {
			pieceHash := piecesBytes[i : i+20]
			fmt.Printf("%x\n", pieceHash)
		}
	} else if command == "peers" {
		filename := os.Args[2]

		// Read the torrent file as bytes
		fileData, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		// Convert bytes to string
		bencodedString := string(fileData)

		// Decode the bencoded dictionary
		decoded, err := decodeBencode(bencodedString)
		if err != nil {
			fmt.Printf("Error decoding bencode: %v\n", err)
			os.Exit(1)
		}

		// Cast to map[string]interface{}
		torrentDict, ok := decoded.(map[string]interface{})
		if !ok {
			fmt.Println("Error: torrent file does not contain a dictionary")
			os.Exit(1)
		}

		// Extract announce (tracker URL)
		announce, ok := torrentDict["announce"]
		if !ok {
			fmt.Println("Error: torrent file missing 'announce' field")
			os.Exit(1)
		}
		announceStr, ok := announce.(string)
		if !ok {
			fmt.Println("Error: 'announce' field is not a string")
			os.Exit(1)
		}

		// Extract info dictionary
		info, ok := torrentDict["info"]
		if !ok {
			fmt.Println("Error: torrent file missing 'info' field")
			os.Exit(1)
		}
		infoDict, ok := info.(map[string]interface{})
		if !ok {
			fmt.Println("Error: 'info' field is not a dictionary")
			os.Exit(1)
		}

		// Extract length from info
		length, ok := infoDict["length"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'length' field")
			os.Exit(1)
		}
		lengthInt, ok := length.(int)
		if !ok {
			fmt.Println("Error: 'length' field is not an integer")
			os.Exit(1)
		}

		// Extract the info dictionary bytes for hashing
		infoBytes, err := findInfoDictionaryBytes(fileData)
		if err != nil {
			fmt.Printf("Error extracting info dictionary: %v\n", err)
			os.Exit(1)
		}

		// Calculate SHA-1 hash (20 bytes)
		hash := sha1.Sum(infoBytes)
		infoHashBytes := hash[:]

		// Generate peer_id (20 bytes) - use a simple 20-character string
		peerID := "01234567890123456789" // 20 bytes

		// Build query parameters
		baseURL, err := url.Parse(announceStr)
		if err != nil {
			fmt.Printf("Error parsing tracker URL: %v\n", err)
			os.Exit(1)
		}

		query := baseURL.Query()
		query.Set("info_hash", string(infoHashBytes))
		query.Set("peer_id", peerID)
		query.Set("port", "6881")
		query.Set("uploaded", "0")
		query.Set("downloaded", "0")
		query.Set("left", strconv.Itoa(lengthInt))
		query.Set("compact", "1")

		baseURL.RawQuery = query.Encode()
		trackerURL := baseURL.String()

		// Make HTTP GET request
		resp, err := http.Get(trackerURL)
		if err != nil {
			fmt.Printf("Error making HTTP request: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Error: tracker returned status code %d\n", resp.StatusCode)
			os.Exit(1)
		}

		// Read response body
		bodyBytes := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				bodyBytes = append(bodyBytes, buf[:n]...)
			}
			if err != nil {
				break
			}
		}

		// Decode the bencoded response
		responseString := string(bodyBytes)
		trackerResponse, err := decodeBencode(responseString)
		if err != nil {
			fmt.Printf("Error decoding tracker response: %v\n", err)
			os.Exit(1)
		}

		// Cast to map[string]interface{}
		trackerDict, ok := trackerResponse.(map[string]interface{})
		if !ok {
			fmt.Println("Error: tracker response is not a dictionary")
			os.Exit(1)
		}

		// Check for tracker errors
		if failureReason, ok := trackerDict["failure reason"]; ok {
			failureStr, ok := failureReason.(string)
			if ok {
				fmt.Printf("Tracker error: %s\n", failureStr)
			} else {
				fmt.Println("Tracker returned an error (failure reason is not a string)")
			}
			os.Exit(1)
		}

		// Extract peers
		peers, ok := trackerDict["peers"]
		if !ok {
			fmt.Println("Error: tracker response missing 'peers' field")
			os.Exit(1)
		}
		peersStr, ok := peers.(string)
		if !ok {
			fmt.Println("Error: 'peers' field is not a string")
			os.Exit(1)
		}

		// Parse compact peer representation (6 bytes per peer: 4 bytes IP, 2 bytes port)
		peersBytes := []byte(peersStr)
		if len(peersBytes)%6 != 0 {
			fmt.Printf("Error: 'peers' length (%d) is not a multiple of 6\n", len(peersBytes))
			os.Exit(1)
		}

		// Parse and print each peer
		for i := 0; i < len(peersBytes); i += 6 {
			peerBytes := peersBytes[i : i+6]
			// First 4 bytes are IP address (IPv4)
			ip := fmt.Sprintf("%d.%d.%d.%d", peerBytes[0], peerBytes[1], peerBytes[2], peerBytes[3])
			// Last 2 bytes are port (big-endian)
			port := binary.BigEndian.Uint16(peerBytes[4:6])
			fmt.Printf("%s:%d\n", ip, port)
		}
	} else if command == "handshake" {
		filename := os.Args[2]
		peerAddress := os.Args[3] // format: "IP:port"

		// Parse peer address
		parts := strings.Split(peerAddress, ":")
		if len(parts) != 2 {
			fmt.Printf("Error: invalid peer address format. Expected IP:port, got: %s\n", peerAddress)
			os.Exit(1)
		}
		peerIP := parts[0]
		peerPort := parts[1]

		// Read the torrent file
		fileData, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		// Extract the info dictionary bytes for hashing
		infoBytes, err := findInfoDictionaryBytes(fileData)
		if err != nil {
			fmt.Printf("Error extracting info dictionary: %v\n", err)
			os.Exit(1)
		}

		// Calculate SHA-1 hash (20 bytes)
		hash := sha1.Sum(infoBytes)
		infoHashBytes := hash[:]

		// Generate random peer_id (20 bytes)
		peerID := make([]byte, 20)
		_, err = rand.Read(peerID)
		if err != nil {
			fmt.Printf("Error generating peer ID: %v\n", err)
			os.Exit(1)
		}

		// Build handshake message
		handshake := make([]byte, 0, 68) // 1 + 19 + 8 + 20 + 20 = 68 bytes
		handshake = append(handshake, 19) // protocol string length
		handshake = append(handshake, []byte("BitTorrent protocol")...)
		handshake = append(handshake, make([]byte, 8)...) // 8 reserved bytes (all zeros)
		handshake = append(handshake, infoHashBytes...)
		handshake = append(handshake, peerID...)

		// Establish TCP connection
		conn, err := net.Dial("tcp", peerIP+":"+peerPort)
		if err != nil {
			fmt.Printf("Error connecting to peer: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		// Send handshake
		_, err = conn.Write(handshake)
		if err != nil {
			fmt.Printf("Error sending handshake: %v\n", err)
			os.Exit(1)
		}

		// Receive handshake response (68 bytes: 1 + 19 + 8 + 20 + 20)
		response := make([]byte, 68)
		totalRead := 0
		for totalRead < 68 {
			n, err := conn.Read(response[totalRead:])
			if err != nil {
				fmt.Printf("Error receiving handshake: %v\n", err)
				os.Exit(1)
			}
			totalRead += n
		}

		// Extract peer ID from response (bytes 48-67, which is the last 20 bytes)
		receivedPeerID := response[48:68]

		// Print peer ID in hexadecimal
		fmt.Printf("Peer ID: %x\n", receivedPeerID)
	} else if command == "download_piece" {
		// Parse arguments: download_piece -o output_file torrent_file piece_index
		if len(os.Args) < 6 || os.Args[2] != "-o" {
			fmt.Println("Usage: download_piece -o <output-file> <torrent-file> <piece-index>")
			os.Exit(1)
		}
		outputFile := os.Args[3]
		filename := os.Args[4]
		pieceIndexStr := os.Args[5]
		pieceIndex, err := strconv.Atoi(pieceIndexStr)
		if err != nil {
			fmt.Printf("Error: invalid piece index: %v\n", err)
			os.Exit(1)
		}

		// Read the torrent file
		fileData, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		// Decode the torrent file
		bencodedString := string(fileData)
		decoded, err := decodeBencode(bencodedString)
		if err != nil {
			fmt.Printf("Error decoding bencode: %v\n", err)
			os.Exit(1)
		}

		torrentDict, ok := decoded.(map[string]interface{})
		if !ok {
			fmt.Println("Error: torrent file does not contain a dictionary")
			os.Exit(1)
		}

		// Extract info dictionary
		info, ok := torrentDict["info"]
		if !ok {
			fmt.Println("Error: torrent file missing 'info' field")
			os.Exit(1)
		}
		infoDict, ok := info.(map[string]interface{})
		if !ok {
			fmt.Println("Error: 'info' field is not a dictionary")
			os.Exit(1)
		}

		// Extract piece length
		pieceLength, ok := infoDict["piece length"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'piece length' field")
			os.Exit(1)
		}
		pieceLengthInt, ok := pieceLength.(int)
		if !ok {
			fmt.Println("Error: 'piece length' field is not an integer")
			os.Exit(1)
		}

		// Extract pieces hashes
		pieces, ok := infoDict["pieces"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'pieces' field")
			os.Exit(1)
		}
		piecesStr, ok := pieces.(string)
		if !ok {
			fmt.Println("Error: 'pieces' field is not a string")
			os.Exit(1)
		}
		piecesBytes := []byte(piecesStr)
		numPieces := len(piecesBytes) / 20
		if pieceIndex < 0 || pieceIndex >= numPieces {
			fmt.Printf("Error: piece index %d is out of range (0-%d)\n", pieceIndex, numPieces-1)
			os.Exit(1)
		}
		expectedPieceHash := piecesBytes[pieceIndex*20 : (pieceIndex+1)*20]

		// Extract length to calculate last piece size
		length, ok := infoDict["length"]
		if !ok {
			fmt.Println("Error: 'info' dictionary missing 'length' field")
			os.Exit(1)
		}
		lengthInt, ok := length.(int)
		if !ok {
			fmt.Println("Error: 'length' field is not an integer")
			os.Exit(1)
		}

		// Calculate actual piece size (last piece might be smaller)
		actualPieceLength := pieceLengthInt
		if pieceIndex == numPieces-1 {
			actualPieceLength = lengthInt - (pieceIndex * pieceLengthInt)
		}

		// Get peers from tracker
		announce, ok := torrentDict["announce"]
		if !ok {
			fmt.Println("Error: torrent file missing 'announce' field")
			os.Exit(1)
		}
		announceStr, ok := announce.(string)
		if !ok {
			fmt.Println("Error: 'announce' field is not a string")
			os.Exit(1)
		}

		// Extract info hash
		infoBytes, err := findInfoDictionaryBytes(fileData)
		if err != nil {
			fmt.Printf("Error extracting info dictionary: %v\n", err)
			os.Exit(1)
		}
		hash := sha1.Sum(infoBytes)
		infoHashBytes := hash[:]

		// Get peers (reuse logic from peers command)
		peerID := "01234567890123456789" // 20 bytes
		baseURL, err := url.Parse(announceStr)
		if err != nil {
			fmt.Printf("Error parsing tracker URL: %v\n", err)
			os.Exit(1)
		}
		query := baseURL.Query()
		query.Set("info_hash", string(infoHashBytes))
		query.Set("peer_id", peerID)
		query.Set("port", "6881")
		query.Set("uploaded", "0")
		query.Set("downloaded", "0")
		query.Set("left", strconv.Itoa(lengthInt))
		query.Set("compact", "1")
		baseURL.RawQuery = query.Encode()
		trackerURL := baseURL.String()

		resp, err := http.Get(trackerURL)
		if err != nil {
			fmt.Printf("Error making HTTP request: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Error: tracker returned status code %d\n", resp.StatusCode)
			os.Exit(1)
		}

		bodyBytes := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				bodyBytes = append(bodyBytes, buf[:n]...)
			}
			if err != nil {
				break
			}
		}

		responseString := string(bodyBytes)
		trackerResponse, err := decodeBencode(responseString)
		if err != nil {
			fmt.Printf("Error decoding tracker response: %v\n", err)
			os.Exit(1)
		}

		trackerDict, ok := trackerResponse.(map[string]interface{})
		if !ok {
			fmt.Println("Error: tracker response is not a dictionary")
			os.Exit(1)
		}

		if failureReason, ok := trackerDict["failure reason"]; ok {
			failureStr, ok := failureReason.(string)
			if ok {
				fmt.Printf("Tracker error: %s\n", failureStr)
			} else {
				fmt.Println("Tracker returned an error")
			}
			os.Exit(1)
		}

		peers, ok := trackerDict["peers"]
		if !ok {
			fmt.Println("Error: tracker response missing 'peers' field")
			os.Exit(1)
		}
		peersStr, ok := peers.(string)
		if !ok {
			fmt.Println("Error: 'peers' field is not a string")
			os.Exit(1)
		}

		peersBytes := []byte(peersStr)
		if len(peersBytes) < 6 {
			fmt.Println("Error: no peers available")
			os.Exit(1)
		}

		// Connect to first peer
		peerBytes := peersBytes[0:6]
		peerIP := fmt.Sprintf("%d.%d.%d.%d", peerBytes[0], peerBytes[1], peerBytes[2], peerBytes[3])
		peerPort := binary.BigEndian.Uint16(peerBytes[4:6])

		// Generate random peer_id for handshake
		handshakePeerID := make([]byte, 20)
		_, err = rand.Read(handshakePeerID)
		if err != nil {
			fmt.Printf("Error generating peer ID: %v\n", err)
			os.Exit(1)
		}

		// Perform handshake
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", peerIP, peerPort))
		if err != nil {
			fmt.Printf("Error connecting to peer: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		handshake := make([]byte, 0, 68)
		handshake = append(handshake, 19)
		handshake = append(handshake, []byte("BitTorrent protocol")...)
		handshake = append(handshake, make([]byte, 8)...)
		handshake = append(handshake, infoHashBytes...)
		handshake = append(handshake, handshakePeerID...)

		_, err = conn.Write(handshake)
		if err != nil {
			fmt.Printf("Error sending handshake: %v\n", err)
			os.Exit(1)
		}

		response := make([]byte, 68)
		totalRead := 0
		for totalRead < 68 {
			n, err := conn.Read(response[totalRead:])
			if err != nil {
				fmt.Printf("Error receiving handshake: %v\n", err)
				os.Exit(1)
			}
			totalRead += n
		}

		// Wait for bitfield message (id 5)
		for {
			msgID, _, err := readPeerMessage(conn)
			if err != nil {
				fmt.Printf("Error reading message: %v\n", err)
				os.Exit(1)
			}
			if msgID == 5 { // bitfield
				break
			}
			// Ignore keep-alive (msgID == 0) and other messages
		}

		// Send interested message (id 2)
		err = sendPeerMessage(conn, 2, nil)
		if err != nil {
			fmt.Printf("Error sending interested: %v\n", err)
			os.Exit(1)
		}

		// Wait for unchoke message (id 1)
		for {
			msgID, _, err := readPeerMessage(conn)
			if err != nil {
				fmt.Printf("Error reading message: %v\n", err)
				os.Exit(1)
			}
			if msgID == 1 { // unchoke
				break
			}
			// Ignore keep-alive (msgID == 0) and other messages
		}

		// Break piece into 16 KiB blocks and request them
		blockSize := 16 * 1024 // 16 KiB
		numBlocks := (actualPieceLength + blockSize - 1) / blockSize // ceiling division
		pieceData := make([]byte, actualPieceLength)
		blocksReceived := make(map[int][]byte) // map of begin offset to block data

		// Send request messages for all blocks
		for i := 0; i < numBlocks; i++ {
			begin := i * blockSize
			blockLength := blockSize
			if begin+blockLength > actualPieceLength {
				blockLength = actualPieceLength - begin
			}

			// Build request message payload: index (4 bytes) + begin (4 bytes) + length (4 bytes)
			payload := make([]byte, 12)
			binary.BigEndian.PutUint32(payload[0:4], uint32(pieceIndex))
			binary.BigEndian.PutUint32(payload[4:8], uint32(begin))
			binary.BigEndian.PutUint32(payload[8:12], uint32(blockLength))

			err = sendPeerMessage(conn, 6, payload) // request message id is 6
			if err != nil {
				fmt.Printf("Error sending request: %v\n", err)
				os.Exit(1)
			}
		}

		// Receive piece messages
		piecesReceived := 0
		for piecesReceived < numBlocks {
			msgID, payload, err := readPeerMessage(conn)
			if err != nil {
				fmt.Printf("Error reading message: %v\n", err)
				os.Exit(1)
			}
			if msgID == 0 {
				// Keep-alive message, ignore
				continue
			}
			if msgID == 7 { // piece message
				if len(payload) < 8 {
					fmt.Printf("Error: piece message too short\n")
					os.Exit(1)
				}
				// Extract index, begin, and block data
				receivedIndex := binary.BigEndian.Uint32(payload[0:4])
				receivedBegin := binary.BigEndian.Uint32(payload[4:8])
				blockData := payload[8:]

				if int(receivedIndex) == pieceIndex {
					blocksReceived[int(receivedBegin)] = blockData
					piecesReceived++
				}
			}
		}

		// Combine blocks into piece
		for begin, blockData := range blocksReceived {
			copy(pieceData[begin:], blockData)
		}

		// Verify piece hash
		pieceHash := sha1.Sum(pieceData)
		if string(pieceHash[:]) != string(expectedPieceHash) {
			fmt.Printf("Error: piece hash mismatch\n")
			os.Exit(1)
		}

		// Write piece to file
		err = os.WriteFile(outputFile, pieceData, 0644)
		if err != nil {
			fmt.Printf("Error writing file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Piece %d downloaded to %s.\n", pieceIndex, outputFile)
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
