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
// Tests for SplitAtStochasticOffset (Requisitos 4.4, 4.5, 4.6)
// ---------------------------------------------------------------------------

// TestSplitAtStochasticOffset_ReturnsTwoFragments verifies that the function
// always returns exactly 2 fragments.
// Requisito 4.4.
func TestSplitAtStochasticOffset_ReturnsTwoFragments(t *testing.T) {
	buf := buildValidTLSClientHello("example.com")
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	fragments, err := SplitAtStochasticOffset(hello)
	if err != nil {
		t.Fatalf("unexpected split error: %v", err)
	}
	if len(fragments) != 2 {
		t.Errorf("expected exactly 2 fragments, got %d", len(fragments))
	}
}

// TestSplitAtStochasticOffset_ConcatenationEqualsOriginal verifies that
// fragment1 ++ fragment2 == hello.Raw.
// Requisito 4.5.
func TestSplitAtStochasticOffset_ConcatenationEqualsOriginal(t *testing.T) {
	buf := buildValidTLSClientHello("secure.example.org")
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	fragments, err := SplitAtStochasticOffset(hello)
	if err != nil {
		t.Fatalf("unexpected split error: %v", err)
	}

	reconstructed := append(fragments[0], fragments[1]...)
	if !bytes.Equal(reconstructed, hello.Raw) {
		t.Errorf("concatenation of fragments does not equal original Raw buffer")
	}
}

// TestSplitAtStochasticOffset_LengthsSum verifies that
// len(fragment1) + len(fragment2) == len(hello.Raw).
// Requisito 4.5.
func TestSplitAtStochasticOffset_LengthsSum(t *testing.T) {
	buf := buildValidTLSClientHello("test.example.net")
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	fragments, err := SplitAtStochasticOffset(hello)
	if err != nil {
		t.Fatalf("unexpected split error: %v", err)
	}

	total := len(fragments[0]) + len(fragments[1])
	if total != len(hello.Raw) {
		t.Errorf("len(f1)+len(f2) = %d, want %d", total, len(hello.Raw))
	}
}

// TestSplitAtStochasticOffset_OffsetWithinSNIRange verifies that the split
// point k falls within [SNIOffset, SNIOffset + SNILength - 1].
// Requisito 4.4.
func TestSplitAtStochasticOffset_OffsetWithinSNIRange(t *testing.T) {
	buf := buildValidTLSClientHello("range-check.example.com")
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	// Run many iterations to exercise the random range.
	for i := 0; i < 200; i++ {
		fragments, err := SplitAtStochasticOffset(hello)
		if err != nil {
			t.Fatalf("iteration %d: unexpected split error: %v", i, err)
		}

		// k == len(fragment1) because fragment1 = Raw[:k]
		k := len(fragments[0])
		lo := hello.SNIOffset
		hi := hello.SNIOffset + hello.SNILength - 1

		if k < lo || k > hi {
			t.Errorf("iteration %d: k=%d not in [%d, %d]", i, k, lo, hi)
		}
	}
}

// TestSplitAtStochasticOffset_SNILengthOne returns an error when SNILength == 1.
// Requisito 4.6 (precondition: SNILength > 1).
func TestSplitAtStochasticOffset_SNILengthOne(t *testing.T) {
	buf := buildValidTLSClientHello("a") // single-char hostname → SNILength == 1
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if hello.SNILength != 1 {
		t.Skipf("hostname 'a' produced SNILength=%d, not 1; skipping", hello.SNILength)
	}

	_, err = SplitAtStochasticOffset(hello)
	if err == nil {
		t.Error("expected error for SNILength == 1, got nil")
	}
}

// TestSplitAtStochasticOffset_NilHello verifies that a nil hello returns an error.
// Requisito 4.6.
func TestSplitAtStochasticOffset_NilHello(t *testing.T) {
	_, err := SplitAtStochasticOffset(nil)
	if err == nil {
		t.Error("expected error for nil hello, got nil")
	}
}

// TestSplitAtStochasticOffset_NilRaw verifies that a hello with nil Raw returns an error.
// Requisito 4.6.
func TestSplitAtStochasticOffset_NilRaw(t *testing.T) {
	hello := &TLSHello{
		Raw:       nil,
		SNIOffset: 10,
		SNILength: 5,
		SNIValue:  "hello",
	}
	_, err := SplitAtStochasticOffset(hello)
	if err == nil {
		t.Error("expected error for nil Raw, got nil")
	}
}

// TestSplitAtStochasticOffset_SNIOffsetZero verifies that SNIOffset == 0 returns an error.
// Requisito 4.6.
func TestSplitAtStochasticOffset_SNIOffsetZero(t *testing.T) {
	hello := &TLSHello{
		Raw:       []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		SNIOffset: 0,
		SNILength: 5,
		SNIValue:  "hello",
	}
	_, err := SplitAtStochasticOffset(hello)
	if err == nil {
		t.Error("expected error for SNIOffset == 0, got nil")
	}
}

// TestSplitAtStochasticOffset_RawTooShort verifies that a Raw buffer shorter
// than SNIOffset + SNILength returns an error.
// Requisito 4.6.
func TestSplitAtStochasticOffset_RawTooShort(t *testing.T) {
	hello := &TLSHello{
		Raw:       []byte{0x16, 0x03, 0x01, 0x00, 0x05},
		SNIOffset: 3,
		SNILength: 5, // 3 + 5 = 8 > 5 (len of Raw)
		SNIValue:  "hello",
	}
	_, err := SplitAtStochasticOffset(hello)
	if err == nil {
		t.Error("expected error for Raw buffer too short, got nil")
	}
}

// TestSplitAtStochasticOffset_LongHostname verifies correct behaviour with a
// long SNI hostname (many possible split points).
// Requisito 4.4, 4.5.
func TestSplitAtStochasticOffset_LongHostname(t *testing.T) {
	hostname := "very-long-hostname-for-testing-purposes.subdomain.example.com"
	buf := buildValidTLSClientHello(hostname)
	hello, err := ParseTLSClientHello(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	fragments, err := SplitAtStochasticOffset(hello)
	if err != nil {
		t.Fatalf("unexpected split error: %v", err)
	}

	if len(fragments) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(fragments))
	}

	reconstructed := append(fragments[0], fragments[1]...)
	if !bytes.Equal(reconstructed, hello.Raw) {
		t.Error("concatenation of fragments does not equal original Raw buffer")
	}
}

// ---------------------------------------------------------------------------
// Property-Based Tests for SplitAtStochasticOffset (Requisitos 4.4, 4.5)
// ---------------------------------------------------------------------------

// buildValidTLSClientHelloWithLength constructs a synthetic TLS ClientHello
// with an SNI hostname of exactly `hostnameLen` bytes (filled with 'a').
// hostnameLen must be >= 2 (SNILength > 1 is required by SplitAtStochasticOffset).
func buildValidTLSClientHelloWithLength(hostnameLen int) []byte {
	hostname := strings.Repeat("a", hostnameLen)
	return buildValidTLSClientHello(hostname)
}

// PropertyTest_SNIByteConservation verifies Property 1: Byte Conservation in
// SNI Fragmentation.
//
// For every valid TLS ClientHello with SNI:
//   - fragment1 ++ fragment2 = rawPacket
//   - len(fragment1) + len(fragment2) = len(rawPacket)
//   - k ∈ [SNIOffset, SNIOffset + SNILength - 1]
//
// **Validates: Requirements 4.4, 4.5**
func PropertyTest_SNIByteConservation(t *testing.T) {
	t.Helper()

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// Generator: SNI hostname lengths in [2, 253].
	// Minimum 2 because SplitAtStochasticOffset requires SNILength > 1.
	// Maximum 253 is the DNS name length limit.
	hostnameLen := gen.IntRange(2, 253)

	properties.Property(
		"fragment1 ++ fragment2 = rawPacket (byte conservation)",
		prop.ForAll(
			func(hLen int) bool {
				buf := buildValidTLSClientHelloWithLength(hLen)
				hello, err := ParseTLSClientHello(buf)
				if err != nil {
					// If parsing fails the packet is not a valid ClientHello;
					// the property only applies to valid packets.
					return true
				}

				fragments, err := SplitAtStochasticOffset(hello)
				if err != nil {
					return false
				}
				if len(fragments) != 2 {
					return false
				}

				// Property: concatenation equals original
				reconstructed := append(fragments[0], fragments[1]...)
				return bytes.Equal(reconstructed, hello.Raw)
			},
			hostnameLen,
		),
	)

	properties.Property(
		"len(fragment1) + len(fragment2) = len(rawPacket) (length conservation)",
		prop.ForAll(
			func(hLen int) bool {
				buf := buildValidTLSClientHelloWithLength(hLen)
				hello, err := ParseTLSClientHello(buf)
				if err != nil {
					return true
				}

				fragments, err := SplitAtStochasticOffset(hello)
				if err != nil {
					return false
				}
				if len(fragments) != 2 {
					return false
				}

				// Property: sum of lengths equals original length
				return len(fragments[0])+len(fragments[1]) == len(hello.Raw)
			},
			hostnameLen,
		),
	)

	properties.Property(
		"k ∈ [SNIOffset, SNIOffset + SNILength - 1] (split point within SNI range)",
		prop.ForAll(
			func(hLen int) bool {
				buf := buildValidTLSClientHelloWithLength(hLen)
				hello, err := ParseTLSClientHello(buf)
				if err != nil {
					return true
				}

				fragments, err := SplitAtStochasticOffset(hello)
				if err != nil {
					return false
				}
				if len(fragments) != 2 {
					return false
				}

				// k == len(fragment1) because fragment1 = Raw[:k]
				k := len(fragments[0])
				lo := hello.SNIOffset
				hi := hello.SNIOffset + hello.SNILength - 1

				return k >= lo && k <= hi
			},
			hostnameLen,
		),
	)

	properties.TestingRun(t)
}

// TestPropertySNIByteConservation is the test entry point for the gopter
// property suite. It runs all three sub-properties of Property 1.
//
// **Validates: Requirements 4.4, 4.5**
func TestPropertySNIByteConservation(t *testing.T) {
	PropertyTest_SNIByteConservation(t)
}
