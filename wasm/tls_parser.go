package main

import (
	"encoding/binary"
	"fmt"
)

// TLSHello holds the parsed fields of a TLS ClientHello record that are
// relevant to the SNI splitter.
type TLSHello struct {
	Raw       []byte // Original raw buffer
	SNIOffset int    // Byte offset of the SNI hostname value within Raw
	SNILength int    // Length in bytes of the SNI hostname value
	SNIValue  string // Decoded SNI hostname
}

// ParseTLSClientHello parses a raw TLS record buffer and extracts the SNI
// (Server Name Indication) field from the ClientHello handshake message.
//
// Preconditions:
//   - buf != nil and len(buf) >= 5 (minimum TLS record header)
//   - buf[0] == 0x16 (TLS Handshake content type)
//   - buf[5] == 0x01 (ClientHello handshake type)
//
// Postconditions (on success):
//   - result.SNIOffset > 0
//   - result.SNILength > 0
//   - result.SNIValue != ""
//   - result.SNIOffset + result.SNILength <= len(buf)
//
// Returns (nil, error) with a descriptive message for any invalid input.
func ParseTLSClientHello(buf []byte) (*TLSHello, error) {
	// --- Validate minimum TLS record header (5 bytes) ---
	if len(buf) < 5 {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer too short (%d bytes), need at least 5 for TLS record header", len(buf))
	}

	// --- Validate TLS Handshake content type ---
	if buf[0] != 0x16 {
		return nil, fmt.Errorf("ParseTLSClientHello: invalid content type 0x%02X, expected 0x16 (TLS Handshake)", buf[0])
	}

	// --- Validate that the handshake message fits in the buffer ---
	// TLS record header: [0]=content_type [1-2]=version [3-4]=length
	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if len(buf) < 5+recordLen {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated: record claims %d bytes but only %d available after header", recordLen, len(buf)-5)
	}

	// --- Validate ClientHello handshake type at buf[5] ---
	if len(buf) < 6 {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer too short to contain handshake type byte")
	}
	if buf[5] != 0x01 {
		return nil, fmt.Errorf("ParseTLSClientHello: invalid handshake type 0x%02X, expected 0x01 (ClientHello)", buf[5])
	}

	// --- Parse Handshake header (4 bytes: type + 3-byte length) ---
	// buf[5]    = HandshakeType (0x01)
	// buf[6-8]  = HandshakeLength (uint24, big-endian)
	if len(buf) < 9 {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer too short to contain handshake header")
	}
	hsBodyLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
	if len(buf) < 9+hsBodyLen {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated: handshake body claims %d bytes but only %d available", hsBodyLen, len(buf)-9)
	}

	// --- Parse ClientHello body ---
	// Offset 9: client_version (2 bytes)
	// Offset 11: random (32 bytes)
	// Offset 43: session_id_length (1 byte)
	off := 9

	// client_version (2 bytes)
	if off+2 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at client_version")
	}
	off += 2 // skip client_version

	// random (32 bytes)
	if off+32 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at random")
	}
	off += 32

	// session_id_length (1 byte) + session_id
	if off+1 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at session_id_length")
	}
	sessionIDLen := int(buf[off])
	off++
	if off+sessionIDLen > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at session_id")
	}
	off += sessionIDLen

	// cipher_suites_length (2 bytes) + cipher_suites
	if off+2 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at cipher_suites_length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2
	if off+cipherSuitesLen > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at cipher_suites")
	}
	off += cipherSuitesLen

	// compression_methods_length (1 byte) + compression_methods
	if off+1 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at compression_methods_length")
	}
	compressionLen := int(buf[off])
	off++
	if off+compressionLen > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at compression_methods")
	}
	off += compressionLen

	// --- Extensions ---
	// If there are no more bytes, there are no extensions (no SNI)
	if off+2 > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: no extensions present, SNI extension not found")
	}
	extensionsLen := int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2
	if off+extensionsLen > len(buf) {
		return nil, fmt.Errorf("ParseTLSClientHello: buffer truncated at extensions block")
	}

	extEnd := off + extensionsLen

	// Iterate over extensions to find SNI (type 0x0000)
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(buf[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		off += 4

		if off+extDataLen > extEnd {
			return nil, fmt.Errorf("ParseTLSClientHello: extension data truncated for type 0x%04X", extType)
		}

		if extType == 0x0000 {
			// SNI extension found
			// Extension data layout:
			//   2 bytes: server_name_list_length
			//   1 byte:  name_type (0x00 = host_name)
			//   2 bytes: name_length
			//   N bytes: hostname
			extData := buf[off : off+extDataLen]
			if len(extData) < 5 {
				return nil, fmt.Errorf("ParseTLSClientHello: SNI extension data too short (%d bytes)", len(extData))
			}

			// server_name_list_length
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if listLen < 3 || 2+listLen > len(extData) {
				return nil, fmt.Errorf("ParseTLSClientHello: SNI server_name_list_length invalid (%d)", listLen)
			}

			// name_type must be 0x00 (host_name)
			nameType := extData[2]
			if nameType != 0x00 {
				return nil, fmt.Errorf("ParseTLSClientHello: unsupported SNI name type 0x%02X, expected 0x00 (host_name)", nameType)
			}

			// name_length
			nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if nameLen == 0 {
				return nil, fmt.Errorf("ParseTLSClientHello: SNI hostname length is zero")
			}
			if 5+nameLen > len(extData) {
				return nil, fmt.Errorf("ParseTLSClientHello: SNI hostname truncated: claims %d bytes but only %d available", nameLen, len(extData)-5)
			}

			// The SNI hostname value starts at: off + 5 (within the extension data)
			// off currently points to the start of extData within buf
			sniOffset := off + 5
			sniValue := string(buf[sniOffset : sniOffset+nameLen])

			// Validate postcondition: SNIOffset + SNILength <= len(buf)
			if sniOffset+nameLen > len(buf) {
				return nil, fmt.Errorf("ParseTLSClientHello: SNI offset+length exceeds buffer bounds")
			}

			return &TLSHello{
				Raw:       buf,
				SNIOffset: sniOffset,
				SNILength: nameLen,
				SNIValue:  sniValue,
			}, nil
		}

		off += extDataLen
	}

	return nil, fmt.Errorf("ParseTLSClientHello: SNI extension (type 0x0000) not found in ClientHello")
}
