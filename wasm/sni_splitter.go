package main

import (
	"fmt"
	"math/rand"
)

// SplitAtStochasticOffset splits a TLS ClientHello packet into exactly 2
// fragments at a uniformly random offset k within the SNI field.
//
// Preconditions:
//   - hello != nil
//   - hello.SNILength > 1  (need at least 2 bytes to split meaningfully)
//   - hello.SNIOffset > 0
//   - hello.Raw != nil AND len(hello.Raw) >= hello.SNIOffset + hello.SNILength
//
// Postconditions:
//   - len(result) == 2
//   - result[0] = hello.Raw[:k]
//   - result[1] = hello.Raw[k:]
//   - Concatenating result[0] and result[1] reproduces hello.Raw exactly
//   - k ∈ [SNIOffset, SNIOffset + SNILength - 1]
//
// Requisitos: 4.4, 4.5, 4.6
func SplitAtStochasticOffset(hello *TLSHello) ([][]byte, error) {
	// --- Validate preconditions ---
	if hello == nil {
		return nil, fmt.Errorf("SplitAtStochasticOffset: hello is nil")
	}
	if hello.Raw == nil {
		return nil, fmt.Errorf("SplitAtStochasticOffset: hello.Raw is nil")
	}
	if hello.SNIOffset <= 0 {
		return nil, fmt.Errorf("SplitAtStochasticOffset: SNIOffset must be > 0, got %d", hello.SNIOffset)
	}
	// Precondition: SNILength > 1 (need at least 2 bytes to produce a meaningful split)
	if hello.SNILength <= 1 {
		return nil, fmt.Errorf("SplitAtStochasticOffset: SNILength must be > 1, got %d", hello.SNILength)
	}
	minRequired := hello.SNIOffset + hello.SNILength
	if len(hello.Raw) < minRequired {
		return nil, fmt.Errorf(
			"SplitAtStochasticOffset: Raw buffer too short: len=%d, need at least SNIOffset(%d)+SNILength(%d)=%d",
			len(hello.Raw), hello.SNIOffset, hello.SNILength, minRequired,
		)
	}

	// --- Compute stochastic offset k ---
	// k is drawn from Uniform([SNIOffset, SNIOffset + SNILength - 1])
	// This guarantees the split point falls within the SNI field.
	lo := hello.SNIOffset
	hi := hello.SNIOffset + hello.SNILength - 1 // inclusive upper bound

	// rand.Intn(n) returns a value in [0, n), so we use (hi - lo + 1) as the range.
	k := lo + rand.Intn(hi-lo+1)

	// --- Produce exactly 2 fragments ---
	// fragment1 = Raw[:k]  (bytes 0 .. k-1)
	// fragment2 = Raw[k:]  (bytes k .. n-1)
	// Concatenation: fragment1 ++ fragment2 == Raw  (Go slice semantics guarantee this)
	fragment1 := hello.Raw[:k]
	fragment2 := hello.Raw[k:]

	return [][]byte{fragment1, fragment2}, nil
}
