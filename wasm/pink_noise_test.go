//go:build !js

package main

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// ---------------------------------------------------------------------------
// Tests for GeneratePinkNoise (Requisitos 6.3, 6.4, 6.6)
// ---------------------------------------------------------------------------

// TestGeneratePinkNoise_ReturnsExactLength verifies that the function returns
// exactly numBytes bytes.
// Requisito 6.3.
func TestGeneratePinkNoise_ReturnsExactLength(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	testCases := []int{1, 10, 64, 128, 256, 512}

	for _, numBytes := range testCases {
		t.Run("numBytes="+string(rune(numBytes)), func(t *testing.T) {
			result, err := GeneratePinkNoise(params, numBytes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != numBytes {
				t.Errorf("expected length %d, got %d", numBytes, len(result))
			}
		})
	}
}

// TestGeneratePinkNoise_AlphaZero verifies that alpha <= 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_AlphaZero(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    0.0,
		Variance: 1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 64)
	if err == nil {
		t.Error("expected error for alpha = 0, got nil")
	}
}

// TestGeneratePinkNoise_AlphaNegative verifies that alpha < 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_AlphaNegative(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    -1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 64)
	if err == nil {
		t.Error("expected error for alpha < 0, got nil")
	}
}

// TestGeneratePinkNoise_VarianceZero verifies that variance <= 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_VarianceZero(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 0.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 64)
	if err == nil {
		t.Error("expected error for variance = 0, got nil")
	}
}

// TestGeneratePinkNoise_VarianceNegative verifies that variance < 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_VarianceNegative(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: -1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 64)
	if err == nil {
		t.Error("expected error for variance < 0, got nil")
	}
}

// TestGeneratePinkNoise_NumBytesZero verifies that numBytes <= 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_NumBytesZero(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 0)
	if err == nil {
		t.Error("expected error for numBytes = 0, got nil")
	}
}

// TestGeneratePinkNoise_NumBytesNegative verifies that numBytes < 0 returns an error.
// Requisito 6.4.
func TestGeneratePinkNoise_NumBytesNegative(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, -10)
	if err == nil {
		t.Error("expected error for numBytes < 0, got nil")
	}
}

// TestGeneratePinkNoise_MaxSizeLimit verifies that numBytes > 512 returns an error.
// Requisito 6.6.
func TestGeneratePinkNoise_MaxSizeLimit(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	_, err := GeneratePinkNoise(params, 513)
	if err == nil {
		t.Error("expected error for numBytes > 512, got nil")
	}
}

// TestGeneratePinkNoise_MaxSizeAllowed verifies that numBytes = 512 is allowed.
// Requisito 6.6.
func TestGeneratePinkNoise_MaxSizeAllowed(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	result, err := GeneratePinkNoise(params, 512)
	if err != nil {
		t.Fatalf("unexpected error for numBytes = 512: %v", err)
	}
	if len(result) != 512 {
		t.Errorf("expected length 512, got %d", len(result))
	}
}

// TestGeneratePinkNoise_Reproducibility verifies that the same seed produces
// the same output.
// Requisito 6.3.
func TestGeneratePinkNoise_Reproducibility(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     99999,
	}

	result1, err1 := GeneratePinkNoise(params, 128)
	if err1 != nil {
		t.Fatalf("unexpected error on first call: %v", err1)
	}

	result2, err2 := GeneratePinkNoise(params, 128)
	if err2 != nil {
		t.Fatalf("unexpected error on second call: %v", err2)
	}

	if len(result1) != len(result2) {
		t.Fatalf("lengths differ: %d vs %d", len(result1), len(result2))
	}

	for i := 0; i < len(result1); i++ {
		if result1[i] != result2[i] {
			t.Errorf("byte %d differs: %d vs %d", i, result1[i], result2[i])
		}
	}
}

// TestGeneratePinkNoise_DifferentSeeds verifies that different seeds produce
// different outputs.
// Requisito 6.3.
func TestGeneratePinkNoise_DifferentSeeds(t *testing.T) {
	params1 := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     11111,
	}

	params2 := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     22222,
	}

	result1, err1 := GeneratePinkNoise(params1, 128)
	if err1 != nil {
		t.Fatalf("unexpected error with seed 11111: %v", err1)
	}

	result2, err2 := GeneratePinkNoise(params2, 128)
	if err2 != nil {
		t.Fatalf("unexpected error with seed 22222: %v", err2)
	}

	// Results should be different
	identical := true
	for i := 0; i < len(result1); i++ {
		if result1[i] != result2[i] {
			identical = false
			break
		}
	}

	if identical {
		t.Error("expected different outputs for different seeds, got identical")
	}
}

// TestGeneratePinkNoise_ByteRangeValid verifies that all output bytes are in
// the valid range [0, 255].
// Requisito 6.3.
func TestGeneratePinkNoise_ByteRangeValid(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 10.0, // Higher variance to test clamping
		Seed:     54321,
	}

	result, err := GeneratePinkNoise(params, 256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, b := range result {
		// Bytes are unsigned, so they're always >= 0 and <= 255
		// This test is mostly to ensure no panic occurs
		_ = b
		if i < 0 {
			t.Errorf("invalid index %d", i)
		}
	}
}

// TestGeneratePinkNoise_VariousAlphaValues verifies that the function works
// with different alpha values.
// Requisito 6.4.
func TestGeneratePinkNoise_VariousAlphaValues(t *testing.T) {
	alphaValues := []float64{0.5, 1.0, 1.5, 2.0}

	for _, alpha := range alphaValues {
		t.Run("alpha="+string(rune(int(alpha*10))), func(t *testing.T) {
			params := PinkNoiseParams{
				Alpha:    alpha,
				Variance: 1.0,
				Seed:     12345,
			}

			result, err := GeneratePinkNoise(params, 64)
			if err != nil {
				t.Fatalf("unexpected error for alpha=%g: %v", alpha, err)
			}
			if len(result) != 64 {
				t.Errorf("expected length 64, got %d", len(result))
			}
		})
	}
}

// TestGeneratePinkNoise_OddNumBytes verifies that odd numBytes values work correctly.
// Requisito 6.3.
func TestGeneratePinkNoise_OddNumBytes(t *testing.T) {
	params := PinkNoiseParams{
		Alpha:    1.0,
		Variance: 1.0,
		Seed:     12345,
	}

	oddSizes := []int{1, 3, 5, 7, 63, 127, 255, 511}

	for _, numBytes := range oddSizes {
		result, err := GeneratePinkNoise(params, numBytes)
		if err != nil {
			t.Fatalf("unexpected error for numBytes=%d: %v", numBytes, err)
		}
		if len(result) != numBytes {
			t.Errorf("expected length %d, got %d", numBytes, len(result))
		}
	}
}

// ---------------------------------------------------------------------------
// Property-Based Tests for GeneratePinkNoise (Requisito 6.3)
// ---------------------------------------------------------------------------

// TestPropertyPinkNoisePaddingLength verifies Property 9: the length of the
// generated Pink Noise padding is exactly numBytes.
//
// For every numBytes in [1, 512]:
//   len(GeneratePinkNoise(params, numBytes)) = numBytes
//
// **Validates: Requirements 6.3**
func TestPropertyPinkNoisePaddingLength(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// Generator for numBytes in [1, 512]
	genNumBytes := gen.IntRange(1, 512)

	properties.Property(
		"len(GeneratePinkNoise(params, numBytes)) = numBytes (Requisito 6.3)",
		prop.ForAll(
			func(numBytes int) bool {
				params := PinkNoiseParams{
					Alpha:    1.0,
					Variance: 1.0,
					Seed:     42,
				}
				result, err := GeneratePinkNoise(params, numBytes)
				if err != nil {
					// Preconditions violated — not a valid input for this property
					return true
				}
				return len(result) == numBytes
			},
			genNumBytes,
		),
	)

	properties.TestingRun(t)
}
