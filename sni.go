package main

import (
	"encoding/binary"
	"fmt"
)

// extractSNI parses a raw TLS ClientHello message and extracts the SNI
// (Server Name Indication) hostname. The input should start with the TLS
// record header (content type 0x16).
//
// Returns empty string if no SNI extension is found.
func extractSNI(data []byte) (string, error) {
	// TLS record: type(1) + version(2) + length(2) + fragment
	if len(data) < 5 {
		return "", fmt.Errorf("too short for TLS record header")
	}
	if data[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record (got 0x%02x)", data[0])
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	fragment := data[5:]
	if len(fragment) < recordLen {
		// We may not have the full record, but try to parse what we have.
		fragment = fragment[:len(fragment)]
	} else {
		fragment = fragment[:recordLen]
	}

	// Handshake: type(1) + length(3) + body
	if len(fragment) < 4 {
		return "", fmt.Errorf("too short for handshake header")
	}
	if fragment[0] != 0x01 { // ClientHello
		return "", fmt.Errorf("not a ClientHello (got 0x%02x)", fragment[0])
	}
	// handshakeLen := int(fragment[1])<<16 | int(fragment[2])<<8 | int(fragment[3])
	body := fragment[4:]

	// ClientHello: version(2) + random(32) + sessionID(1+var) + cipherSuites(2+var) + compression(1+var) + extensions(2+var)
	if len(body) < 34 {
		return "", fmt.Errorf("too short for ClientHello fixed fields")
	}
	pos := 34 // skip version + random

	// Session ID
	if pos >= len(body) {
		return "", fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen

	// Cipher suites
	if pos+2 > len(body) {
		return "", fmt.Errorf("truncated at cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2 + cipherSuitesLen

	// Compression methods
	if pos >= len(body) {
		return "", fmt.Errorf("truncated at compression methods")
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(body) {
		return "", nil // No extensions — no SNI
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(body) {
		extensionsEnd = len(body)
	}

	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(body[pos:])
		extLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+extLen > extensionsEnd {
			break
		}

		if extType == 0x0000 { // SNI extension
			extData := body[pos : pos+extLen]
			return parseSNIExtension(extData)
		}
		pos += extLen
	}

	return "", nil // No SNI extension found
}

// parseSNIExtension parses the SNI extension data and returns the hostname.
func parseSNIExtension(data []byte) (string, error) {
	// ServerNameList: length(2) + list of ServerName entries
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(data))
	list := data[2:]
	if len(list) < listLen {
		list = list[:len(list)]
	} else {
		list = list[:listLen]
	}

	pos := 0
	for pos+3 <= len(list) {
		nameType := list[pos]
		nameLen := int(binary.BigEndian.Uint16(list[pos+1:]))
		pos += 3
		if pos+nameLen > len(list) {
			break
		}

		if nameType == 0x00 { // host_name
			return string(list[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}

	return "", nil
}
