package main

import "fmt"

// EKFState holds the state of a scalar Extended Kalman Filter used to
// estimate network bandwidth and generate noise-shaping parameters.
//
// Fields:
//   X  – current state estimate (bandwidth, bytes/s)
//   P  – error covariance (estimation uncertainty)
//   Q  – process noise covariance  (must be > 0)
//   R  – measurement noise covariance (must be > 0)
//   K  – Kalman gain from the last update cycle
//
// Requisitos: 7.1, 7.2, 7.3, 7.4, 7.5
type EKFState struct {
	X float64 // State estimate
	P float64 // Error covariance
	Q float64 // Process noise covariance
	R float64 // Measurement noise covariance
	K float64 // Kalman gain (last computed)
}

// EKFUpdateCycle runs one full predict-then-update cycle of the scalar EKF.
//
// The model is linear and scalar:
//   Transition:  f(x) = x   (bandwidth assumed constant between samples)
//   Observation: h(x) = x   (direct measurement)
//
// Prediction phase:
//   x_pred = ekf.X
//   P_pred = ekf.P + ekf.Q
//
// Update phase:
//   innovation = measurementZ - x_pred
//   S          = P_pred + ekf.R
//   K          = P_pred / S
//   x_updated  = x_pred + K * innovation
//   P_updated  = (1 - K) * P_pred
//
// Non-negativity constraint:
//   ekf.X = max(0.0, x_updated)
//
// Preconditions:
//   - ekf.Q > 0
//   - ekf.R > 0
//   - measurementZ >= 0  (caller responsibility; not enforced here per spec)
//
// Postconditions:
//   - ekf.P > 0
//   - ekf.K ∈ [0.0, 1.0]
//   - ekf.X >= 0
//
// Returns the mutated *EKFState and nil on success, or (nil, error) if
// preconditions are violated.
//
// Requisitos: 7.1, 7.2, 7.3, 7.4, 7.5
func EKFUpdateCycle(ekf *EKFState, measurementZ float64) (*EKFState, error) {
	if ekf == nil {
		return nil, fmt.Errorf("EKFUpdateCycle: ekf state is nil")
	}
	if ekf.Q <= 0 {
		return nil, fmt.Errorf("EKFUpdateCycle: Q must be > 0, got %g", ekf.Q)
	}
	if ekf.R <= 0 {
		return nil, fmt.Errorf("EKFUpdateCycle: R must be > 0, got %g", ekf.R)
	}

	// --- PREDICTION PHASE ---
	xPred := ekf.X
	pPred := ekf.P + ekf.Q

	// --- UPDATE PHASE ---
	innovation := measurementZ - xPred
	s := pPred + ekf.R        // Innovation covariance
	k := pPred / s            // Kalman gain  ∈ (0, 1) since pPred > 0 and R > 0

	xUpdated := xPred + k*innovation
	pUpdated := (1.0 - k) * pPred

	// Apply non-negativity constraint on the state estimate
	if xUpdated < 0.0 {
		xUpdated = 0.0
	}

	ekf.X = xUpdated
	ekf.P = pUpdated
	ekf.K = k

	return ekf, nil
}
