package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
