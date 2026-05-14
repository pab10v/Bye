//go:build !js

package main

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// ---------------------------------------------------------------------------
// Property-Based Tests for EKFUpdateCycle (Requisitos 7.1, 7.2, 7.3)
// ---------------------------------------------------------------------------

// TestPropertyEKFMathematicalInvariants verifies Property 4: Mathematical
// invariants of the EKF in each update cycle.
//
// For every measurement z >= 0 and parameters Q, R in (0, 100]:
//   - P > 0  (error covariance is always positive)
//   - K ∈ [0.0, 1.0]  (Kalman gain is bounded)
//   - X >= 0  (state estimate is non-negative)
//
// **Validates: Requirements 7.1, 7.2, 7.3**
func TestPropertyEKFMathematicalInvariants(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// Generator for measurement z in [0, 1e9]
	genZ := gen.Float64Range(0, 1e9)

	// Generator for Q and R in (0, 100].
	// We use (0.001, 100] to avoid floating-point issues at exactly 0.
	genQ := gen.Float64Range(0.001, 100.0)
	genR := gen.Float64Range(0.001, 100.0)

	// Generator for initial state X in [0, 1e9] (non-negative bandwidth estimate)
	genX := gen.Float64Range(0, 1e9)

	// Generator for initial covariance P in (0, 1e6] (must be positive)
	genP := gen.Float64Range(0.001, 1e6)

	// Property: P > 0 after every update cycle
	properties.Property(
		"P > 0 after EKF update cycle (Requisito 7.1)",
		prop.ForAll(
			func(z, q, r, x, p float64) bool {
				ekf := &EKFState{
					X: x,
					P: p,
					Q: q,
					R: r,
					K: 0.0,
				}
				result, err := EKFUpdateCycle(ekf, z)
				if err != nil {
					// Preconditions violated — not a valid input for this property
					return true
				}
				return result.P > 0
			},
			genZ, genQ, genR, genX, genP,
		),
	)

	// Property: K ∈ [0.0, 1.0] after every update cycle
	properties.Property(
		"K ∈ [0.0, 1.0] after EKF update cycle (Requisito 7.2)",
		prop.ForAll(
			func(z, q, r, x, p float64) bool {
				ekf := &EKFState{
					X: x,
					P: p,
					Q: q,
					R: r,
					K: 0.0,
				}
				result, err := EKFUpdateCycle(ekf, z)
				if err != nil {
					return true
				}
				return result.K >= 0.0 && result.K <= 1.0
			},
			genZ, genQ, genR, genX, genP,
		),
	)

	// Property: X >= 0 after every update cycle
	properties.Property(
		"X >= 0 after EKF update cycle (Requisito 7.3)",
		prop.ForAll(
			func(z, q, r, x, p float64) bool {
				ekf := &EKFState{
					X: x,
					P: p,
					Q: q,
					R: r,
					K: 0.0,
				}
				result, err := EKFUpdateCycle(ekf, z)
				if err != nil {
					return true
				}
				return result.X >= 0.0
			},
			genZ, genQ, genR, genX, genP,
		),
	)

	// Combined property: all three invariants hold simultaneously
	properties.Property(
		"P > 0 AND K ∈ [0.0, 1.0] AND X >= 0 simultaneously (Requisitos 7.1, 7.2, 7.3)",
		prop.ForAll(
			func(z, q, r, x, p float64) bool {
				ekf := &EKFState{
					X: x,
					P: p,
					Q: q,
					R: r,
					K: 0.0,
				}
				result, err := EKFUpdateCycle(ekf, z)
				if err != nil {
					return true
				}
				return result.P > 0 &&
					result.K >= 0.0 && result.K <= 1.0 &&
					result.X >= 0.0
			},
			genZ, genQ, genR, genX, genP,
		),
	)

	properties.TestingRun(t)
}

// ---------------------------------------------------------------------------
// Unit Tests for EKFUpdateCycle (Requisitos 7.4, 6.4)
// ---------------------------------------------------------------------------

// TestEKFUpdateCycle_QZeroReturnsError verifies that EKFUpdateCycle returns
// an error when Q = 0.
// Requisito 7.4.
func TestEKFUpdateCycle_QZeroReturnsError(t *testing.T) {
	ekf := &EKFState{
		X: 100.0,
		P: 1.0,
		Q: 0.0, // invalid
		R: 1.0,
		K: 0.0,
	}

	_, err := EKFUpdateCycle(ekf, 100.0)
	if err == nil {
		t.Error("expected error for Q = 0, got nil")
	}
}

// TestEKFUpdateCycle_QNegativeReturnsError verifies that EKFUpdateCycle returns
// an error when Q < 0.
// Requisito 7.4.
func TestEKFUpdateCycle_QNegativeReturnsError(t *testing.T) {
	ekf := &EKFState{
		X: 100.0,
		P: 1.0,
		Q: -1.0, // invalid
		R: 1.0,
		K: 0.0,
	}

	_, err := EKFUpdateCycle(ekf, 100.0)
	if err == nil {
		t.Error("expected error for Q < 0, got nil")
	}
}

// TestEKFUpdateCycle_ConvergesWithConstantSignal verifies that after many
// update cycles with a constant measurement, the state estimate X converges
// toward that constant value.
// Requisito 7.4.
func TestEKFUpdateCycle_ConvergesWithConstantSignal(t *testing.T) {
	const constantSignal = 500.0
	const numCycles = 200
	const tolerance = 1.0 // X must be within 1.0 of the constant signal

	ekf := &EKFState{
		X: 0.0,   // start far from the true value
		P: 1000.0, // high initial uncertainty
		Q: 1.0,
		R: 10.0,
		K: 0.0,
	}

	var err error
	for i := 0; i < numCycles; i++ {
		ekf, err = EKFUpdateCycle(ekf, constantSignal)
		if err != nil {
			t.Fatalf("unexpected error at cycle %d: %v", i, err)
		}
	}

	diff := ekf.X - constantSignal
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("EKF did not converge: X = %g, expected ~%g (tolerance %g)", ekf.X, constantSignal, tolerance)
	}
}
