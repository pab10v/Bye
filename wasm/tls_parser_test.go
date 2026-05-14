//go:build !js

package main

import (
	"strings"
	"testing"
)

// buildValidTLSClientHello constructs a minimal but valid TLS 1.2 ClientHello
// with a single SNI extension for the given hostname.
//
// Wire format (simplified):
//
//	TLS Record Header (5 bytes):
//	  [0]    0x16        Content-Type: Handshake
//	  [1-2]  0x03 0x01   Legacy version: TLS 1.0
//	  [3-4]  length      Length of the handshake message (big-endian uint16)
//
//	Handshake Header (4 bytes):
//	  [5]    0x01        HandshakeType: ClientHello
//	  [6-8]  length      Length of ClientHello body (big-endian uint24)
//
//	ClientHello Body:
//	  [9-10]  0x03 0x03  Client version: TLS 1.2
//	  [11-42] random     32 bytes of random data
//	  [43]    0x00       Session ID length = 0
//	  [44-45] 0x00 0x02  Cipher suites length = 2
//	  [46-47] 0x00 0x2F  Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
//	  [48]    0x01        Compression methods length = 1
//	  [49]    0x00        Compression method: null
//	  [50-51] ext_len    Extensions total length (big-endian uint16)
//
//	SNI Extension:
//	  [52-53] 0x00 0x00  Extension type: server_name (0)
//	  [54-55] ext_data_len
//	  [56-57] list_len
//	  [58]    0x00       Name type: host_name
//	  [59-60] name_len
//	  [61...] hostname bytes
func buildValidTLSClientHello(hostname string) []byte {
	hostnameBytes := []byte(hostname)
	hostnameLen := len(hostnameBytes)

	// SNI extension data layout:
	//   2 bytes: server name list length
	//   1 byte:  name type (0x00 = host_name)
	//   2 bytes: name length
	//   N bytes: hostname
	sniListLen := 1 + 2 + hostnameLen // type + name_len + hostname
	sniExtDataLen := 2 + sniListLen   // list_len field + list

	// Extensions block:
	//   2 bytes: extension type
	//   2 bytes: extension data length
	//   N bytes: extension data
	extBlockLen := 2 + 2 + sniExtDataLen

	// ClientHello body (after the 4-byte handshake header):
	//   2  client version
	//   32 random
	//   1  session id length
	//   2  cipher suites length
	//   2  cipher suite
	//   1  compression methods length
	//   1  compression method
	//   2  extensions length
	//   N  extensions
	chBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extBlockLen

	// Handshake message = 4-byte header + body
	hsLen := 4 + chBodyLen

	// TLS record = 5-byte header + handshake message
	buf := make([]byte, 5+hsLen)

	// --- TLS Record Header ---
	buf[0] = 0x16 // Content-Type: Handshake
	buf[1] = 0x03 // Legacy version major
	buf[2] = 0x01 // Legacy version minor
	buf[3] = byte(hsLen >> 8)
	buf[4] = byte(hsLen)

	// --- Handshake Header ---
	buf[5] = 0x01 // HandshakeType: ClientHello
	buf[6] = byte(chBodyLen >> 16)
	buf[7] = byte(chBodyLen >> 8)
	buf[8] = byte(chBodyLen)

	// --- ClientHello Body ---
	off := 9
	buf[off] = 0x03
	buf[off+1] = 0x03 // Client version: TLS 1.2
	off += 2

	// 32 bytes random (zeroed for test purposes)
	off += 32

	buf[off] = 0x00 // Session ID length = 0
	off++

	buf[off] = 0x00
	buf[off+1] = 0x02 // Cipher suites length = 2
	off += 2
	buf[off] = 0x00
	buf[off+1] = 0x2F // TLS_RSA_WITH_AES_128_CBC_SHA
	off += 2

	buf[off] = 0x01 // Compression methods length = 1
	off++
	buf[off] = 0x00 // null compression
	off++

	// Extensions total length
	buf[off] = byte(extBlockLen >> 8)
	buf[off+1] = byte(extBlockLen)
	off += 2

	// --- SNI Extension ---
	buf[off] = 0x00
	buf[off+1] = 0x00 // Extension type: server_name
	off += 2
	buf[off] = byte(sniExtDataLen >> 8)
	buf[off+1] = byte(sniExtDataLen)
	off += 2

	// Server name list length
	buf[off] = byte(sniListLen >> 8)
	buf[off+1] = byte(sniListLen)
	off += 2

	buf[off] = 0x00 // Name type: host_name
	off++

	buf[off] = byte(hostnameLen >> 8)
	buf[off+1] = byte(hostnameLen)
	off += 2

	copy(buf[off:], hostnameBytes)

	return buf
}

// buildClientHelloWithoutSNI builds a valid TLS ClientHello that has no extensions.
func buildClientHelloWithoutSNI() []byte {
	// ClientHello body (no extensions):
	//   2  client version
	//   32 random
	//   1  session id length
	//   2  cipher suites length
	//   2  cipher suite
	//   1  compression methods length
	//   1  compression method
	chBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1
	hsLen := 4 + chBodyLen

	buf := make([]byte, 5+hsLen)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x01
	buf[3] = byte(hsLen >> 8)
	buf[4] = byte(hsLen)

	buf[5] = 0x01
	buf[6] = byte(chBodyLen >> 16)
	buf[7] = byte(chBodyLen >> 8)
	buf[8] = byte(chBodyLen)

	off := 9
	buf[off] = 0x03
	buf[off+1] = 0x03
	off += 2
	off += 32     // random
	buf[off] = 0x00 // session id length
	off++
	buf[off] = 0x00
	buf[off+1] = 0x02
	off += 2
	buf[off] = 0x00
	buf[off+1] = 0x2F
	off += 2
	buf[off] = 0x01
	off++
	buf[off] = 0x00
	// No extensions length field — no extensions present

	return buf
}

// ---------------------------------------------------------------------------
// Tests for ParseTLSClientHello (Requisitos 4.1, 4.2)
// ---------------------------------------------------------------------------

// TestParseTLSClientHello_ValidClientHello verifies that a well-formed TLS
// ClientHello with an SNI extension is parsed correctly.
// Requisito 4.1: SNIOffset > 0, SNILength > 0, SNIValue non-empty.
func TestParseTLSClientHello_ValidClientHello(t *testing.T) {
	hostname := "example.com"
	buf := buildValidTLSClientHello(hostname)

	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("expected no error for valid ClientHello, got: %v", err)
	}
	if hello == nil {
		t.Fatal("expected non-nil TLSHello, got nil")
	}
	if hello.SNIOffset <= 0 {
		t.Errorf("expected SNIOffset > 0, got %d", hello.SNIOffset)
	}
	if hello.SNILength <= 0 {
		t.Errorf("expected SNILength > 0, got %d", hello.SNILength)
	}
	if hello.SNIValue == "" {
		t.Error("expected non-empty SNIValue, got empty string")
	}
	if hello.SNIValue != hostname {
		t.Errorf("expected SNIValue %q, got %q", hostname, hello.SNIValue)
	}
}

// TestParseTLSClientHello_SNIOffsetWithinBounds verifies that the reported
// SNIOffset and SNILength are consistent with the raw buffer bounds.
// Requisito 4.1.
func TestParseTLSClientHello_SNIOffsetWithinBounds(t *testing.T) {
	buf := buildValidTLSClientHello("secure.example.org")

	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hello.SNIOffset+hello.SNILength > len(buf) {
		t.Errorf(
			"SNIOffset(%d) + SNILength(%d) = %d exceeds buffer length %d",
			hello.SNIOffset, hello.SNILength,
			hello.SNIOffset+hello.SNILength,
			len(buf),
		)
	}
}

// TestParseTLSClientHello_EmptyBuffer verifies that an empty buffer returns a
// descriptive error and no result.
// Requisito 4.2.
func TestParseTLSClientHello_EmptyBuffer(t *testing.T) {
	hello, err := ParseTLSClientHello([]byte{})
	if err == nil {
		t.Fatal("expected error for empty buffer, got nil")
	}
	if hello != nil {
		t.Errorf("expected nil TLSHello for empty buffer, got %+v", hello)
	}
	if err.Error() == "" {
		t.Error("expected descriptive error message, got empty string")
	}
}

// TestParseTLSClientHello_NilBuffer verifies that a nil buffer returns a
// descriptive error and no result.
// Requisito 4.2.
func TestParseTLSClientHello_NilBuffer(t *testing.T) {
	hello, err := ParseTLSClientHello(nil)
	if err == nil {
		t.Fatal("expected error for nil buffer, got nil")
	}
	if hello != nil {
		t.Errorf("expected nil TLSHello for nil buffer, got %+v", hello)
	}
}

// TestParseTLSClientHello_TruncatedBuffer verifies that a buffer shorter than
// the minimum 5-byte TLS record header returns a descriptive error.
// Requisito 4.2.
func TestParseTLSClientHello_TruncatedBuffer(t *testing.T) {
	truncatedCases := []struct {
		name string
		buf  []byte
	}{
		{"1 byte", []byte{0x16}},
		{"2 bytes", []byte{0x16, 0x03}},
		{"3 bytes", []byte{0x16, 0x03, 0x01}},
		{"4 bytes", []byte{0x16, 0x03, 0x01, 0x00}},
	}

	for _, tc := range truncatedCases {
		t.Run(tc.name, func(t *testing.T) {
			hello, err := ParseTLSClientHello(tc.buf)
			if err == nil {
				t.Fatalf("expected error for truncated buffer (%d bytes), got nil", len(tc.buf))
			}
			if hello != nil {
				t.Errorf("expected nil TLSHello for truncated buffer, got %+v", hello)
			}
			if err.Error() == "" {
				t.Error("expected descriptive error message, got empty string")
			}
		})
	}
}

// TestParseTLSClientHello_InvalidContentType verifies that a buffer whose
// first byte is not 0x16 (TLS Handshake) returns a descriptive error.
// Requisito 4.2.
func TestParseTLSClientHello_InvalidContentType(t *testing.T) {
	invalidTypes := []byte{0x00, 0x14, 0x15, 0x17, 0x18, 0xFF}

	for _, ct := range invalidTypes {
		buf := buildValidTLSClientHello("example.com")
		buf[0] = ct // overwrite content type

		hello, err := ParseTLSClientHello(buf)
		if err == nil {
			t.Errorf("expected error for content type 0x%02X, got nil", ct)
			continue
		}
		if hello != nil {
			t.Errorf("expected nil TLSHello for content type 0x%02X, got %+v", ct, hello)
		}
		if err.Error() == "" {
			t.Errorf("expected descriptive error for content type 0x%02X, got empty string", ct)
		}
	}
}

// TestParseTLSClientHello_InvalidHandshakeType verifies that a buffer with
// buf[5] != 0x01 (not a ClientHello) returns a descriptive error.
// Requisito 4.2.
func TestParseTLSClientHello_InvalidHandshakeType(t *testing.T) {
	invalidHsTypes := []byte{0x00, 0x02, 0x0B, 0x0C, 0x0E, 0xFF}

	for _, ht := range invalidHsTypes {
		buf := buildValidTLSClientHello("example.com")
		buf[5] = ht // overwrite handshake type

		hello, err := ParseTLSClientHello(buf)
		if err == nil {
			t.Errorf("expected error for handshake type 0x%02X, got nil", ht)
			continue
		}
		if hello != nil {
			t.Errorf("expected nil TLSHello for handshake type 0x%02X, got %+v", ht, hello)
		}
	}
}

// TestParseTLSClientHello_NoSNIExtension verifies that a valid ClientHello
// without an SNI extension returns a descriptive error.
// Requisito 4.2.
func TestParseTLSClientHello_NoSNIExtension(t *testing.T) {
	buf := buildClientHelloWithoutSNI()

	hello, err := ParseTLSClientHello(buf)
	if err == nil {
		t.Fatal("expected error for ClientHello without SNI extension, got nil")
	}
	if hello != nil {
		t.Errorf("expected nil TLSHello when SNI is absent, got %+v", hello)
	}
	if err.Error() == "" {
		t.Error("expected descriptive error message, got empty string")
	}
}

// TestParseTLSClientHello_ErrorMessageIsDescriptive verifies that error
// messages are non-trivial (not just "error" or a single character).
// Requisito 4.2.
func TestParseTLSClientHello_ErrorMessageIsDescriptive(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"truncated", []byte{0x16, 0x03}},
		{"wrong content type", func() []byte {
			b := buildValidTLSClientHello("x.com")
			b[0] = 0x17
			return b
		}()},
		{"no SNI", buildClientHelloWithoutSNI()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTLSClientHello(tc.buf)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			msg := err.Error()
			if len(msg) < 5 {
				t.Errorf("error message too short to be descriptive: %q", msg)
			}
			// Should not be a generic Go zero-value error string
			if strings.EqualFold(msg, "error") {
				t.Errorf("error message is not descriptive: %q", msg)
			}
		})
	}
}

// TestParseTLSClientHello_LongHostname verifies that a hostname at the upper
// end of the valid SNI range (253 chars) is parsed correctly.
// Requisito 4.1.
func TestParseTLSClientHello_LongHostname(t *testing.T) {
	// Max valid DNS name length is 253 characters
	hostname := strings.Repeat("a", 63) + "." +
		strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." +
		strings.Repeat("d", 61) // total = 63+1+63+1+63+1+61 = 253

	buf := buildValidTLSClientHello(hostname)

	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected error for long hostname: %v", err)
	}
	if hello.SNIValue != hostname {
		t.Errorf("expected SNIValue %q, got %q", hostname, hello.SNIValue)
	}
	if hello.SNILength != len(hostname) {
		t.Errorf("expected SNILength %d, got %d", len(hostname), hello.SNILength)
	}
}

// TestParseTLSClientHello_RawPreserved verifies that the Raw field in the
// returned struct contains the original buffer bytes.
// Requisito 4.1.
func TestParseTLSClientHello_RawPreserved(t *testing.T) {
	buf := buildValidTLSClientHello("raw-check.example.com")

	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hello.Raw) != len(buf) {
		t.Errorf("expected Raw length %d, got %d", len(buf), len(hello.Raw))
	}
	for i, b := range buf {
		if hello.Raw[i] != b {
			t.Errorf("Raw[%d] = 0x%02X, want 0x%02X", i, hello.Raw[i], b)
			break
		}
	}
}
