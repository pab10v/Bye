//go:build !js

package main

import (
	"encoding/hex"
	"sync"
)

// State codes for ObfuscateStream.
const (
	StateSPLIT    = 0x01
	StateDISORDER = 0x02
	StateCHAFF    = 0x03
)

// globalEKF is the module-level EKF state used by ObfuscateStream.
// Initialized with X=0, P=1.0, Q=0.1, R=1.0, K=0 per spec.
var globalEKF = &EKFState{
	X: 0,
	P: 1.0,
	Q: 0.1,
	R: 1.0,
	K: 0,
}

// sync.Pool instances for the three canonical buffer sizes.
var (
	pool512B = &sync.Pool{
		New: func() any {
			buf := make([]byte, 512)
			return &buf
		},
	}
	pool4KB = &sync.Pool{
		New: func() any {
			buf := make([]byte, 4096)
			return &buf
		},
	}
	pool64KB = &sync.Pool{
		New: func() any {
			buf := make([]byte, 65536)
			return &buf
		},
	}
)

// acquireWorkBuf returns a pooled work buffer of at least minSize bytes.
// The caller must call releaseWorkBuf when done.
func acquireWorkBuf(minSize int) *[]byte {
	switch {
	case minSize <= 512:
		return pool512B.Get().(*[]byte)
	case minSize <= 4096:
		return pool4KB.Get().(*[]byte)
	default:
		return pool64KB.Get().(*[]byte)
	}
}

// releaseWorkBuf returns a work buffer to the appropriate pool.
func releaseWorkBuf(buf *[]byte) {
	switch cap(*buf) {
	case 512:
		pool512B.Put(buf)
	case 4096:
		pool4KB.Put(buf)
	case 65536:
		pool64KB.Put(buf)
	// Buffers with non-standard capacities are simply discarded.
	}
}

// AdjustTCPWindow adjusts the TCP window size field (bytes 14–15 in a raw TCP
// segment) to the given threshold value.
//
// Preconditions:
//   - If len(buf) < 16, the buffer is returned unchanged.
//
// Postconditions:
//   - buf[14] and buf[15] encode threshold in big-endian order.
//   - All other bytes are unchanged.
//
// Requisitos: 5.2, 5.3
func AdjustTCPWindow(buf []byte, threshold uint16) []byte {
	if len(buf) < 16 {
		return buf
	}
	// Work on a copy so the original is not mutated.
	out := make([]byte, len(buf))
	copy(out, buf)
	out[14] = byte(threshold >> 8)
	out[15] = byte(threshold)
	return out
}

// InjectDummyHeaders prepends a dummy "X-Pad: <hex>" header to buf using up
// to 32 bytes of Pink Noise as the header value.
//
// Postconditions:
//   - The returned buffer starts with "X-Pad: <hex-encoded noise bytes>\r\n".
//   - The original buf bytes follow immediately after the header.
//
// Requisitos: 6.1, 6.2
func InjectDummyHeaders(buf []byte, noise *PinkNoiseParams) []byte {
	const maxNoiseBytes = 32

	noiseBytes, err := GeneratePinkNoise(*noise, maxNoiseBytes)
	if err != nil {
		// If noise generation fails, return the buffer unchanged.
		return buf
	}

	header := []byte("X-Pad: " + hex.EncodeToString(noiseBytes) + "\r\n")

	// Acquire a work buffer large enough for header + payload.
	needed := len(header) + len(buf)
	workBufPtr := acquireWorkBuf(needed)
	defer releaseWorkBuf(workBufPtr)

	// Build result: header ++ buf.
	result := make([]byte, needed)
	copy(result, header)
	copy(result[len(header):], buf)
	return result
}

// ApplyNoiseShaping is a lightweight EKF-aware pass over a single chunk.
// At this transport layer the operation is conceptual: the chunk is returned
// as-is, but the global EKF state is updated with the chunk length as the
// measurement so that subsequent calls reflect the observed traffic volume.
//
// Requisitos: 6.5, 11.3
func ApplyNoiseShaping(chunk []byte, ekf *EKFState) []byte {
	// Update EKF with the chunk length as the observable measurement.
	// Errors are intentionally ignored here; the chunk is always returned.
	_, _ = EKFUpdateCycle(ekf, float64(len(chunk)))
	return chunk
}

// ObfuscateStream applies transport-layer obfuscation to rawBuffer according
// to the requested state code.
//
// State codes:
//   0x01 (SPLIT)    – TLS ClientHello SNI fragmentation
//   0x02 (DISORDER) – TCP window size adjustment via EKF threshold
//   0x03 (CHAFF)    – Dummy X-Pad header injection with Pink Noise
//
// In all cases EKF.ApplyNoiseShaping is applied to every resulting chunk.
//
// Preconditions:
//   - rawBuffer may be nil or empty; the function handles both gracefully.
//   - state ∈ {0x01, 0x02, 0x03}; unknown states return the buffer unchanged.
//
// Postconditions:
//   - Returns ([][]byte, nil) on success.
//   - The TLS encrypted payload is preserved; only transport layout is modified.
//   - State 0x01 + valid TLS ClientHello  → exactly 2 fragments.
//   - State 0x01 + non-TLS buffer         → single-element slice (unchanged).
//   - State 0x02                          → single-element slice (window adjusted).
//   - State 0x03                          → single-element slice (headers injected).
//
// Requisitos: 4.6, 4.7, 5.1, 5.2, 5.3, 6.1, 6.2, 6.5, 11.3
func ObfuscateStream(rawBuffer []byte, state int) ([][]byte, error) {
	var chunks [][]byte

	switch state {
	case StateSPLIT:
		// --- State 0x01: SNI fragmentation ---
		hello, err := ParseTLSClientHello(rawBuffer)
		if err != nil {
			// Not a valid TLS ClientHello — return buffer unchanged.
			chunks = [][]byte{rawBuffer}
		} else {
			frags, splitErr := SplitAtStochasticOffset(hello)
			if splitErr != nil {
				// Split preconditions not met (e.g. SNILength == 1) — return unchanged.
				chunks = [][]byte{rawBuffer}
			} else {
				chunks = frags
			}
		}

	case StateDISORDER:
		// --- State 0x02: TCP window adjustment ---
		// Use the current EKF state estimate as the threshold (clamped to uint16).
		_, _ = EKFUpdateCycle(globalEKF, float64(len(rawBuffer)))
		threshold := uint16(globalEKF.X)
		adjusted := AdjustTCPWindow(rawBuffer, threshold)
		chunks = [][]byte{adjusted}

	case StateCHAFF:
		// --- State 0x03: Dummy header injection with Pink Noise ---
		// Derive Pink Noise parameters from the current EKF state.
		_, _ = EKFUpdateCycle(globalEKF, float64(len(rawBuffer)))
		noiseParams := &PinkNoiseParams{
			Alpha:    1.0,
			Variance: globalEKF.P + 0.1, // ensure Variance > 0
			Seed:     int64(globalEKF.X*1000) + int64(len(rawBuffer)),
		}
		padded := InjectDummyHeaders(rawBuffer, noiseParams)
		chunks = [][]byte{padded}

	default:
		// Unknown state — return buffer unchanged.
		chunks = [][]byte{rawBuffer}
	}

	// Apply EKF noise shaping to every chunk (all three states).
	for i, chunk := range chunks {
		chunks[i] = ApplyNoiseShaping(chunk, globalEKF)
	}

	return chunks, nil
}
