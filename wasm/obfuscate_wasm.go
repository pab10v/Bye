//go:build js && wasm

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
	}
}

// AdjustTCPWindow adjusts the TCP window size field (bytes 14–15 in a raw TCP
// segment) to the given threshold value.
func AdjustTCPWindow(buf []byte, threshold uint16) []byte {
	if len(buf) < 16 {
		return buf
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	out[14] = byte(threshold >> 8)
	out[15] = byte(threshold)
	return out
}

// InjectDummyHeaders prepends a dummy "X-Pad: <hex>" header to buf using up
// to 32 bytes of Pink Noise as the header value.
func InjectDummyHeaders(buf []byte, noise *PinkNoiseParams) []byte {
	const maxNoiseBytes = 32

	noiseBytes, err := GeneratePinkNoise(*noise, maxNoiseBytes)
	if err != nil {
		return buf
	}

	header := []byte("X-Pad: " + hex.EncodeToString(noiseBytes) + "\r\n")

	needed := len(header) + len(buf)
	workBufPtr := acquireWorkBuf(needed)
	defer releaseWorkBuf(workBufPtr)

	result := make([]byte, needed)
	copy(result, header)
	copy(result[len(header):], buf)
	return result
}

// ApplyNoiseShaping updates the global EKF with the chunk length and returns
// the chunk unchanged.
func ApplyNoiseShaping(chunk []byte, ekf *EKFState) []byte {
	_, _ = EKFUpdateCycle(ekf, float64(len(chunk)))
	return chunk
}

// ObfuscateStream applies transport-layer obfuscation to rawBuffer according
// to the requested state code.
//
// Requisitos: 4.6, 4.7, 5.1, 5.2, 5.3, 6.1, 6.2, 6.5, 11.3
func ObfuscateStream(rawBuffer []byte, state int) ([][]byte, error) {
	var chunks [][]byte

	switch state {
	case StateSPLIT:
		hello, err := ParseTLSClientHello(rawBuffer)
		if err != nil {
			chunks = [][]byte{rawBuffer}
		} else {
			frags, splitErr := SplitAtStochasticOffset(hello)
			if splitErr != nil {
				chunks = [][]byte{rawBuffer}
			} else {
				chunks = frags
			}
		}

	case StateDISORDER:
		_, _ = EKFUpdateCycle(globalEKF, float64(len(rawBuffer)))
		threshold := uint16(globalEKF.X)
		adjusted := AdjustTCPWindow(rawBuffer, threshold)
		chunks = [][]byte{adjusted}

	case StateCHAFF:
		_, _ = EKFUpdateCycle(globalEKF, float64(len(rawBuffer)))
		noiseParams := &PinkNoiseParams{
			Alpha:    1.0,
			Variance: globalEKF.P + 0.1,
			Seed:     int64(globalEKF.X*1000) + int64(len(rawBuffer)),
		}
		padded := InjectDummyHeaders(rawBuffer, noiseParams)
		chunks = [][]byte{padded}

	default:
		chunks = [][]byte{rawBuffer}
	}

	for i, chunk := range chunks {
		chunks[i] = ApplyNoiseShaping(chunk, globalEKF)
	}

	return chunks, nil
}
