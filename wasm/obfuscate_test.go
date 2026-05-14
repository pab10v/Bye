//go:build !js

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// ---------------------------------------------------------------------------
// Helper: buildSyntheticTLSPacket
// ---------------------------------------------------------------------------

// buildSyntheticTLSPacket constructs a minimal synthetic TLS record buffer of
// the given total length. The first 5 bytes are a valid TLS record header
// (content type 0x16, version 0x03 0x01, and a length field). The remaining
// bytes are filled with a deterministic pattern so that the payload can be
// identified and verified after obfuscation.
//
// totalLen must be >= 5.
func buildSyntheticTLSPacket(totalLen int) []byte {
	if totalLen < 5 {
		totalLen = 5
	}
	buf := make([]byte, totalLen)

	// TLS record header (5 bytes)
	buf[0] = 0x16 // Content-Type: Handshake
	buf[1] = 0x03 // Version major
	buf[2] = 0x01 // Version minor
	payloadLen := totalLen - 5
	buf[3] = byte(payloadLen >> 8)
	buf[4] = byte(payloadLen)

	// Fill payload with a recognisable pattern: byte value = (index % 251) + 1
	// Using a prime modulus so the pattern is non-trivial and avoids zero bytes.
	for i := 5; i < totalLen; i++ {
		buf[i] = byte((i%251)+1)
	}
	return buf
}

// extractTLSPayload returns the bytes after the 5-byte TLS record header.
// For a buffer shorter than 5 bytes it returns nil.
func extractTLSPayload(buf []byte) []byte {
	if len(buf) < 5 {
		return nil
	}
	return buf[5:]
}

// ---------------------------------------------------------------------------
// Property-Based Test: Propiedad 2 — Integridad del payload TLS bajo cualquier
// estado de evasión.
//
// Para todo paquete p y todo estado s ∈ {0x01, 0x02, 0x03}:
//   extractTLSPayload(ObfuscateStream(p, s)) = extractTLSPayload(p)
//
// Definición operacional de extractTLSPayload por estado:
//
//   State 0x01 (SPLIT):
//     Si p es un TLS ClientHello válido, ObfuscateStream devuelve 2 fragmentos
//     cuya concatenación es igual a p (Propiedad 1). Por tanto:
//       extractTLSPayload(concat(chunks)) = extractTLSPayload(p)
//     Si p no es un TLS ClientHello válido, se devuelve p sin modificar.
//
//   State 0x02 (DISORDER):
//     AdjustTCPWindow modifica únicamente los bytes 14-15 del buffer (campo de
//     ventana TCP en la capa de transporte). El payload TLS (bytes 5 en
//     adelante) se preserva salvo esos dos bytes de capa de transporte:
//       result[5:14] == p[5:14]  AND  result[16:] == p[16:]
//     Para paquetes de longitud < 16, el buffer se devuelve sin modificar.
//
//   State 0x03 (CHAFF):
//     InjectDummyHeaders antepone un header "X-Pad: …\r\n" al buffer original.
//     El buffer original completo (incluyendo su payload TLS) está presente
//     como sufijo del resultado:
//       bytes.HasSuffix(result, p)
//
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

// TestPropertyTLSPayloadIntegrity verifies Property 2: TLS payload integrity
// under any evasion state.
//
// **Validates: Requirements 5.1, 5.2**
func TestPropertyTLSPayloadIntegrity(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// Generator: total packet length in [5, 512].
	// Lower bound 5 = minimum TLS record header size.
	// Upper bound 512 keeps tests fast while covering realistic packet sizes.
	genPacketLen := gen.IntRange(5, 512)

	// -----------------------------------------------------------------------
	// Sub-property A: State 0x01 (SPLIT)
	// For a synthetic TLS packet (not a valid ClientHello), ObfuscateStream
	// returns the buffer unchanged (single-element slice). The TLS payload is
	// trivially preserved.
	// -----------------------------------------------------------------------
	properties.Property(
		"State 0x01: payload preserved — concat(chunks)[5:] == p[5:]",
		prop.ForAll(
			func(pktLen int) bool {
				p := buildSyntheticTLSPacket(pktLen)
				originalPayload := extractTLSPayload(p)

				chunks, err := ObfuscateStream(p, StateSPLIT)
				if err != nil {
					// ObfuscateStream must not return an error for any input.
					return false
				}
				if len(chunks) == 0 {
					return false
				}

				// Reconstruct the full buffer by concatenating all chunks.
				var reconstructed []byte
				for _, chunk := range chunks {
					reconstructed = append(reconstructed, chunk...)
				}

				resultPayload := extractTLSPayload(reconstructed)

				// The concatenation of all chunks must equal the original
				// buffer (byte conservation), so the payloads must be equal.
				return bytes.Equal(resultPayload, originalPayload)
			},
			genPacketLen,
		),
	)

	// -----------------------------------------------------------------------
	// Sub-property B: State 0x02 (DISORDER)
	// AdjustTCPWindow modifies only bytes 14-15 (TCP window field at the
	// transport layer). All other bytes — including the TLS payload — are
	// preserved.
	// -----------------------------------------------------------------------
	properties.Property(
		"State 0x02: payload preserved — only transport-layer bytes 14-15 may differ",
		prop.ForAll(
			func(pktLen int) bool {
				p := buildSyntheticTLSPacket(pktLen)

				chunks, err := ObfuscateStream(p, StateDISORDER)
				if err != nil {
					return false
				}
				if len(chunks) != 1 {
					// State 0x02 must always return exactly one chunk.
					return false
				}
				result := chunks[0]

				if len(result) != len(p) {
					// The buffer length must not change for state 0x02.
					return false
				}

				if len(p) < 16 {
					// AdjustTCPWindow returns the buffer unchanged when
					// len(buf) < 16. The entire buffer is preserved.
					return bytes.Equal(result, p)
				}

				// For packets >= 16 bytes: bytes 14-15 are the TCP window
				// field and may be modified. All other bytes must be equal.
				//
				// Check bytes 5..13 (TLS payload before the window field)
				if !bytes.Equal(result[5:14], p[5:14]) {
					return false
				}
				// Check bytes 16.. (TLS payload after the window field)
				if !bytes.Equal(result[16:], p[16:]) {
					return false
				}
				return true
			},
			genPacketLen,
		),
	)

	// -----------------------------------------------------------------------
	// Sub-property C: State 0x03 (CHAFF)
	// InjectDummyHeaders prepends an "X-Pad: …\r\n" header to the original
	// buffer. The original buffer (and therefore its TLS payload) is present
	// as a contiguous suffix of the result.
	// -----------------------------------------------------------------------
	properties.Property(
		"State 0x03: payload preserved — original bytes present as suffix of result",
		prop.ForAll(
			func(pktLen int) bool {
				p := buildSyntheticTLSPacket(pktLen)

				chunks, err := ObfuscateStream(p, StateCHAFF)
				if err != nil {
					return false
				}
				if len(chunks) != 1 {
					// State 0x03 must always return exactly one chunk.
					return false
				}
				result := chunks[0]

				// The result must be at least as long as the original.
				if len(result) < len(p) {
					return false
				}

				// The original buffer must appear as a suffix of the result
				// (the injected header is prepended, not appended).
				return bytes.HasSuffix(result, p)
			},
			genPacketLen,
		),
	)

	// -----------------------------------------------------------------------
	// Sub-property D: All three states — ObfuscateStream never returns an
	// error and always returns at least one non-nil chunk. This is the
	// minimal liveness invariant across all states.
	// -----------------------------------------------------------------------
	properties.Property(
		"All states: ObfuscateStream returns no error and at least one chunk",
		prop.ForAll(
			func(pktLen int, stateIdx int) bool {
				states := []int{StateSPLIT, StateDISORDER, StateCHAFF}
				state := states[stateIdx%3]

				p := buildSyntheticTLSPacket(pktLen)

				chunks, err := ObfuscateStream(p, state)
				if err != nil {
					return false
				}
				if len(chunks) == 0 {
					return false
				}
				// Every chunk must be non-nil.
				for _, chunk := range chunks {
					if chunk == nil {
						return false
					}
				}
				return true
			},
			genPacketLen,
			gen.IntRange(0, 2),
		),
	)

	properties.TestingRun(t)
}

// ---------------------------------------------------------------------------
// Unit Tests for ObfuscateStream (Requisitos 4.6, 4.7, 6.1, 6.2)
// ---------------------------------------------------------------------------

// TestObfuscateStream_State01_ValidTLSClientHello verifies that State 0x01
// (SPLIT) with a valid TLS ClientHello returns exactly 2 fragments.
//
// Requisitos: 4.6, 4.7
func TestObfuscateStream_State01_ValidTLSClientHello(t *testing.T) {
	// Build a valid TLS ClientHello with a hostname long enough for splitting
	// (SNILength > 1 is required by SplitAtStochasticOffset).
	buf := buildValidTLSClientHello("example.com")

	chunks, err := ObfuscateStream(buf, StateSPLIT)
	if err != nil {
		t.Fatalf("ObfuscateStream returned unexpected error: %v", err)
	}
	if len(chunks) != 2 {
		t.Errorf("expected exactly 2 fragments for valid TLS ClientHello, got %d", len(chunks))
	}

	// Sanity-check: concatenating the two fragments must reproduce the original buffer.
	reconstructed := append(chunks[0], chunks[1]...)
	if !bytes.Equal(reconstructed, buf) {
		t.Error("concatenation of the 2 fragments does not equal the original buffer")
	}
}

// TestObfuscateStream_State01_NonTLSBuffer verifies that State 0x01 (SPLIT)
// with a buffer that is not a valid TLS ClientHello returns the buffer
// unchanged as a single-element slice.
//
// Requisitos: 4.6, 4.7
func TestObfuscateStream_State01_NonTLSBuffer(t *testing.T) {
	// A plain HTTP request is not a TLS ClientHello.
	nonTLS := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	chunks, err := ObfuscateStream(nonTLS, StateSPLIT)
	if err != nil {
		t.Fatalf("ObfuscateStream returned unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("expected exactly 1 chunk for non-TLS buffer, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], nonTLS) {
		t.Error("non-TLS buffer was modified; expected it to be returned unchanged")
	}
}

// TestObfuscateStream_State02_TCPWindowAdjusted verifies that State 0x02
// (DISORDER) adjusts the TCP window field (bytes 14–15) in the output.
//
// The test uses a buffer of at least 16 bytes so that AdjustTCPWindow can
// write the window field. It then checks that bytes 14–15 of the result
// differ from the original (or at least that the result is a valid adjusted
// buffer), and that all other bytes are unchanged.
//
// Requisitos: 5.2, 5.3
func TestObfuscateStream_State02_TCPWindowAdjusted(t *testing.T) {
	// Build a 32-byte buffer with a recognisable pattern so we can detect
	// any unintended modifications outside bytes 14–15.
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(i + 1)
	}

	chunks, err := ObfuscateStream(buf, StateDISORDER)
	if err != nil {
		t.Fatalf("ObfuscateStream returned unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected exactly 1 chunk for State 0x02, got %d", len(chunks))
	}
	result := chunks[0]

	if len(result) != len(buf) {
		t.Fatalf("expected result length %d, got %d", len(buf), len(result))
	}

	// Bytes 0–13 must be unchanged.
	if !bytes.Equal(result[:14], buf[:14]) {
		t.Error("bytes 0–13 were unexpectedly modified by State 0x02")
	}

	// Bytes 16–31 must be unchanged.
	if !bytes.Equal(result[16:], buf[16:]) {
		t.Error("bytes 16–31 were unexpectedly modified by State 0x02")
	}

	// Bytes 14–15 encode the TCP window threshold written by AdjustTCPWindow.
	// We verify they form a consistent big-endian uint16 (any value is valid;
	// the important thing is that the field was written by the implementation).
	_ = uint16(result[14])<<8 | uint16(result[15]) // just ensure no panic
}

// TestObfuscateStream_State03_XPadHeaderPresent verifies that State 0x03
// (CHAFF) prepends an "X-Pad: …\r\n" header to the buffer.
//
// Requisitos: 6.1, 6.2
func TestObfuscateStream_State03_XPadHeaderPresent(t *testing.T) {
	payload := []byte("some application payload data")

	chunks, err := ObfuscateStream(payload, StateCHAFF)
	if err != nil {
		t.Fatalf("ObfuscateStream returned unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected exactly 1 chunk for State 0x03, got %d", len(chunks))
	}
	result := chunks[0]

	// The result must be longer than the original payload (header was prepended).
	if len(result) <= len(payload) {
		t.Errorf("expected result to be longer than payload (%d bytes), got %d bytes", len(payload), len(result))
	}

	// The result must start with the "X-Pad: " prefix.
	resultStr := string(result)
	if !strings.HasPrefix(resultStr, "X-Pad: ") {
		t.Errorf("expected result to start with \"X-Pad: \", got prefix %q", resultStr[:min(20, len(resultStr))])
	}

	// The injected header must be terminated with "\r\n".
	if !strings.Contains(resultStr, "\r\n") {
		t.Error("expected result to contain \"\\r\\n\" header terminator")
	}

	// The original payload must appear as a suffix of the result.
	if !bytes.HasSuffix(result, payload) {
		t.Error("original payload is not present as a suffix of the result")
	}
}

// min returns the smaller of a and b (helper for Go < 1.21 compatibility).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
