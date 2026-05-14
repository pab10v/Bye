/**
 * MarkovFSM — Stochastic Finite State Machine based on Markov Chain
 *
 * Determines the active evasion strategy per session. Transitions between
 * states are updated in real-time with P2P mesh telemetry.
 *
 * States:
 *   0x01 (SPLIT)    — Stochastic SNI fragmentation
 *   0x02 (DISORDER) — TCP window adjustment with constant threshold
 *   0x03 (CHAFF)    — Dummy header injection with Pink Noise padding
 *
 * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7
 */

import {
  EvasionState,
  EVASION_STATE,
  NetworkMetrics,
  TransitionWeights,
  TransitionMatrix,
  DEFAULT_TRANSITION_MATRIX,
} from './types.js';

/** Minimum probability per cell to guarantee ergodicity (REQ 8.6) */
const MIN_CELL_VALUE = 0.01;

/** Number of states in the FSM */
const NUM_STATES = 3;

/** Maps EvasionState codes to matrix row/column indices */
function stateToIndex(state: EvasionState): number {
  switch (state) {
    case EVASION_STATE.SPLIT:    return 0;
    case EVASION_STATE.DISORDER: return 1;
    case EVASION_STATE.CHAFF:    return 2;
    default: return 0; // unreachable — all EvasionState values are covered above
  }
}

/** Maps matrix row/column indices back to EvasionState codes */
function indexToState(index: number): EvasionState {
  switch (index) {
    case 0: return EVASION_STATE.SPLIT;
    case 1: return EVASION_STATE.DISORDER;
    case 2: return EVASION_STATE.CHAFF;
    default: return EVASION_STATE.SPLIT;
  }
}

/**
 * Normalizes a row so that all values sum to 1.0.
 * Also enforces the ergodicity constraint: no cell may be < MIN_CELL_VALUE.
 *
 * The enforcement order is:
 *   1. Clamp each cell to [MIN_CELL_VALUE, 1.0]
 *   2. Normalize so the row sums to 1.0
 *   3. Re-clamp and re-normalize until stable (handles edge cases)
 */
function normalizeRow(row: number[]): number[] {
  const result = [...row];

  // Enforce minimum per cell (ergodicity)
  for (let j = 0; j < NUM_STATES; j++) {
    if (result[j] < MIN_CELL_VALUE) {
      result[j] = MIN_CELL_VALUE;
    }
  }

  // Normalize to sum = 1.0
  const sum = result.reduce((acc, v) => acc + v, 0);
  if (sum <= 0) {
    // Degenerate case: reset to uniform
    return Array(NUM_STATES).fill(1 / NUM_STATES);
  }

  for (let j = 0; j < NUM_STATES; j++) {
    result[j] = result[j] / sum;
  }

  return result;
}

/**
 * Validates that a 3×3 TransitionMatrix has rows that sum to 1.0
 * and all values in [0.0, 1.0].
 *
 * Throws if the matrix is structurally invalid (wrong dimensions).
 */
function validateMatrix(matrix: TransitionMatrix): void {
  if (matrix.length !== NUM_STATES) {
    throw new Error(`TransitionMatrix must have ${NUM_STATES} rows, got ${matrix.length}`);
  }
  for (let i = 0; i < NUM_STATES; i++) {
    if (matrix[i].length !== NUM_STATES) {
      throw new Error(`TransitionMatrix row ${i} must have ${NUM_STATES} columns, got ${matrix[i].length}`);
    }
  }
}

/**
 * Creates a deep copy of a 3×3 matrix.
 */
function cloneMatrix(matrix: TransitionMatrix): TransitionMatrix {
  return matrix.map(row => [...row]);
}

/**
 * Builds a valid initial transition matrix from the default uniform distribution,
 * applying the ergodicity constraint and normalization.
 */
function buildInitialMatrix(): TransitionMatrix {
  const matrix = cloneMatrix(DEFAULT_TRANSITION_MATRIX);
  for (let i = 0; i < NUM_STATES; i++) {
    matrix[i] = normalizeRow(matrix[i]);
  }
  return matrix;
}

// ---------------------------------------------------------------------------
// MarkovFSM interface (matches design spec)
// ---------------------------------------------------------------------------

export interface MarkovFSMInterface {
  getCurrentState(): EvasionState;
  transition(networkConditions: NetworkMetrics): EvasionState;
  updateTransitionMatrix(weights: TransitionWeights): void;
  getTransitionProbabilities(): TransitionMatrix;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class MarkovFSM implements MarkovFSMInterface {
  private currentState: EvasionState;
  private matrix: TransitionMatrix;

  constructor(initialState: EvasionState = EVASION_STATE.SPLIT) {
    this.currentState = initialState;
    this.matrix = buildInitialMatrix();
  }

  /**
   * Returns the currently active evasion state.
   * REQ 8.7
   */
  getCurrentState(): EvasionState {
    return this.currentState;
  }

  /**
   * Returns a deep copy of the current transition probability matrix.
   * REQ 8.1, 8.2
   */
  getTransitionProbabilities(): TransitionMatrix {
    return cloneMatrix(this.matrix);
  }

  /**
   * Performs a Markov transition using roulette wheel selection.
   *
   * If dpiDetectionScore > 0.7, the probability of transitioning to SPLIT
   * is increased by 0.3 and the row is renormalized before selection.
   *
   * The internal matrix is NOT permanently modified by the DPI adjustment —
   * the adjustment is applied to a temporary copy for this transition only.
   *
   * REQ 8.3, 8.4
   */
  transition(metrics: NetworkMetrics): EvasionState {
    const stateIndex = stateToIndex(this.currentState);

    // Work on a temporary copy of the row so the permanent matrix is unchanged
    let row = [...this.matrix[stateIndex]];

    // Dynamic adjustment: high DPI detection score → bias toward SPLIT (index 0)
    if (metrics.dpiDetectionScore > 0.7) {
      row[0] += 0.3;
      row = normalizeRow(row);
    }

    // Roulette wheel selection
    const r = Math.random();
    let cumulative = 0.0;

    for (let j = 0; j < NUM_STATES; j++) {
      cumulative += row[j];
      if (r <= cumulative) {
        this.currentState = indexToState(j);
        return this.currentState;
      }
    }

    // Fallback: stay in current state (should not happen with a valid row)
    return this.currentState;
  }

  /**
   * Updates a single transition weight in the matrix and renormalizes the
   * affected row to maintain the stochastic property.
   *
   * Also enforces the ergodicity constraint (min 0.01 per cell).
   *
   * REQ 8.5, 8.6
   */
  updateTransitionMatrix(weights: TransitionWeights): void {
    const fromIndex = stateToIndex(weights.fromState);
    const toIndex   = stateToIndex(weights.toState);

    // Update the specific cell
    this.matrix[fromIndex][toIndex] = weights.weight;

    // Renormalize the affected row (also enforces ergodicity)
    this.matrix[fromIndex] = normalizeRow(this.matrix[fromIndex]);
  }

  /**
   * Replaces the entire transition matrix.
   * Validates dimensions, normalizes all rows, and enforces ergodicity.
   *
   * REQ 8.1, 8.2, 8.6
   */
  setTransitionMatrix(matrix: TransitionMatrix): void {
    validateMatrix(matrix);
    const newMatrix = cloneMatrix(matrix);
    for (let i = 0; i < NUM_STATES; i++) {
      newMatrix[i] = normalizeRow(newMatrix[i]);
    }
    this.matrix = newMatrix;
  }

  /**
   * Manually overrides the current state (used for testing or user interaction).
   */
  setManualState(state: EvasionState): void {
    this.currentState = state;
  }
}

// ---------------------------------------------------------------------------
// Singleton factory (matches usage pattern in the rest of the codebase)
// ---------------------------------------------------------------------------

let _instance: MarkovFSM | null = null;

export function getMarkovFSM(): MarkovFSM {
  if (!_instance) {
    _instance = new MarkovFSM();
  }
  return _instance;
}

/** Resets the singleton (useful for testing). */
export function resetMarkovFSM(): void {
  _instance = null;
}
