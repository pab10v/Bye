/**
 * StrategyEvaluator — Gradient-Based TransitionMatrix Learning (Layer 4)
 *
 * Tracks per-state connection outcomes and automatically adjusts the Markov
 * TransitionMatrix using a gradient update rule, closing the feedback loop
 * that the existing system lacks.
 *
 * Key behaviors:
 *   - Records success/failure outcomes per EvasionState in rolling windows (max 100)
 *   - Applies ±0.05 gradient step to TransitionMatrix columns when success rate
 *     exceeds 0.7 (positive) or falls below 0.3 (negative)
 *   - Rate-limited to at most one update per 30 seconds
 *   - Defers to mesh intelligence when MeshNode is connected + recent telemetry
 *   - Suspends updates during FORCE_TACTIC manual override
 *   - Outcome recording continues even when paused (toggle only affects updates)
 *
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9,
 *               6.4, 6.5, 6.9, 8.6, 8.7, 8.8
 */

import {
  EvasionState,
  EVASION_STATE,
  ConnectionOutcome,
  StateStats,
  EvaluatorState,
  TransitionMatrix,
  DEFAULT_TRANSITION_MATRIX,
} from './types.js';
import { MarkovFSM } from './markov_fsm.js';
import { MeshNode } from './mesh_node.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Fixed learning-rate increment applied per gradient update (REQ 5.6, 5.7) */
export const GRADIENT_STEP = 0.05;

/** Minimum outcomes in a window before a gradient update is considered (REQ 5.5) */
export const MIN_OUTCOMES_FOR_UPDATE = 10;

/** Success rate threshold above which a positive gradient step is applied (REQ 5.6) */
export const SUCCESS_THRESHOLD = 0.7;

/** Success rate threshold below which a negative gradient step is applied (REQ 5.7) */
export const FAILURE_THRESHOLD = 0.3;

/** Minimum milliseconds between gradient updates to prevent oscillation (REQ 5.9) */
export const UPDATE_COOLDOWN_MS = 30_000;

/** Maximum number of outcomes retained per EvasionState (REQ 5.4) */
export const WINDOW_SIZE = 100;

/** Mesh deferral window: skip gradient update if mesh telemetry is this fresh (REQ 8.7) */
export const MESH_DEFERRAL_MS = 60_000;

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface StrategyEvaluatorInterface {
  /**
   * Records the outcome of a completed connection.
   * Called by handleNetworkStream after each request completes.
   */
  recordOutcome(
    state: EvasionState,
    latencyMs: number,
    failed: boolean,
    baselineLatencyMs: number,
  ): void;

  /** Returns the current evaluator state for the monitor popup. */
  getState(): EvaluatorState;

  /** Clears all outcomes and resets the TransitionMatrix to uniform. */
  reset(): void;

  /** Toggles between active and paused. Returns the new active state. */
  toggle(): boolean;

  /** Returns true if gradient updates are currently active. */
  isActive(): boolean;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class StrategyEvaluator implements StrategyEvaluatorInterface {
  /** Whether gradient updates are currently active (paused = false) */
  private active: boolean;

  /** Timestamp of the last gradient update, null if never updated */
  private lastGradientUpdateAt: number | null = null;

  /** Rolling windows of outcomes per EvasionState */
  private windows: Record<EvasionState, ConnectionOutcome[]> = {
    [EVASION_STATE.SPLIT]:    [],
    [EVASION_STATE.DISORDER]: [],
    [EVASION_STATE.CHAFF]:    [],
  };

  /** Reference to the MarkovFSM singleton for matrix updates */
  private markovFSM: MarkovFSM;

  /** Reference to the MeshNode singleton for mesh deferral check */
  private meshNode: MeshNode;

  /**
   * Getter for the manual override flag (FORCE_TACTIC guard).
   * Injected from background.ts to avoid circular dependencies.
   */
  private getManualOverrideActive: () => boolean;

  /**
   * Getter for the last mesh telemetry timestamp.
   * Injected from background.ts so the evaluator can check mesh deferral.
   */
  private getLastMeshTelemetryAt: () => number;

  constructor(
    markovFSM: MarkovFSM,
    meshNode: MeshNode,
    config: { enabled?: boolean },
    getManualOverrideActive: () => boolean,
    getLastMeshTelemetryAt: () => number,
  ) {
    this.markovFSM = markovFSM;
    this.meshNode = meshNode;
    this.active = config.enabled ?? false;
    this.getManualOverrideActive = getManualOverrideActive;
    this.getLastMeshTelemetryAt = getLastMeshTelemetryAt;
  }

  // -------------------------------------------------------------------------
  // recordOutcome
  // -------------------------------------------------------------------------

  /**
   * Records the outcome of a completed connection.
   *
   * Classification (REQ 5.2, 5.3):
   *   - 'failure' if `failed` is true OR `latencyMs - baselineLatencyMs >= 500`
   *   - 'success' otherwise
   *
   * Appends to the rolling window for the given state, evicting the oldest
   * entry if the window exceeds WINDOW_SIZE (REQ 5.4).
   *
   * Then attempts a gradient update (REQ 5.5–5.9).
   */
  recordOutcome(
    state: EvasionState,
    latencyMs: number,
    failed: boolean,
    baselineLatencyMs: number,
  ): void {
    // Step 1: Classify outcome (REQ 5.2, 5.3)
    const result: 'success' | 'failure' =
      failed || latencyMs - baselineLatencyMs >= 500 ? 'failure' : 'success';

    // Step 2: Append to rolling window
    const outcome: ConnectionOutcome = {
      state,
      result,
      latencyMs,
      timestamp: Date.now(),
    };
    this.windows[state].push(outcome);

    // Step 3: Evict oldest if over capacity (REQ 5.4)
    if (this.windows[state].length > WINDOW_SIZE) {
      this.windows[state].shift();
    }

    // Step 4: Attempt gradient update
    this.maybeApplyGradientUpdate();
  }

  // -------------------------------------------------------------------------
  // maybeApplyGradientUpdate
  // -------------------------------------------------------------------------

  /**
   * Applies a gradient update to the TransitionMatrix if all guards pass.
   *
   * Guards (in order):
   *   1. Skip if paused (REQ 8.2 / 6.9)
   *   2. Skip if FORCE_TACTIC manual override is active (REQ 8.8)
   *   3. Skip if within the 30-second cooldown window (REQ 5.9)
   *   4. Skip if mesh is connected and telemetry is fresh (< 60 s) (REQ 8.7)
   *
   * For each state with ≥ MIN_OUTCOMES_FOR_UPDATE outcomes (REQ 5.5):
   *   - successRate > SUCCESS_THRESHOLD → apply +GRADIENT_STEP to that column (REQ 5.6)
   *   - successRate < FAILURE_THRESHOLD → apply -GRADIENT_STEP (clamped to 0) (REQ 5.7)
   *
   * If any update was applied, calls markovFSM.setTransitionMatrix() to
   * renormalize and enforce ergodicity (REQ 5.8, 8.6).
   */
  private maybeApplyGradientUpdate(): void {
    // Guard 1: skip if paused
    if (!this.active) {
      return;
    }

    // Guard 2: skip if FORCE_TACTIC manual override is active (REQ 8.8)
    if (this.getManualOverrideActive()) {
      return;
    }

    // Guard 3: rate limit — at most once per 30 seconds (REQ 5.9)
    if (
      this.lastGradientUpdateAt !== null &&
      Date.now() - this.lastGradientUpdateAt < UPDATE_COOLDOWN_MS
    ) {
      return;
    }

    // Guard 4: defer to mesh intelligence when connected + recent telemetry (REQ 8.7)
    if (
      this.meshNode.getMode() === 'connected' &&
      Date.now() - this.getLastMeshTelemetryAt() < MESH_DEFERRAL_MS
    ) {
      return;
    }

    // Fetch a fresh copy of the current transition matrix
    const matrix: TransitionMatrix = this.markovFSM.getTransitionProbabilities();

    let updated = false;

    // Iterate over all three states
    const states: EvasionState[] = [
      EVASION_STATE.SPLIT,    // index 0
      EVASION_STATE.DISORDER, // index 1
      EVASION_STATE.CHAFF,    // index 2
    ];

    for (const state of states) {
      const window = this.windows[state];

      // REQ 5.5: need at least MIN_OUTCOMES_FOR_UPDATE outcomes
      if (window.length < MIN_OUTCOMES_FOR_UPDATE) {
        continue;
      }

      const successCount = window.filter(o => o.result === 'success').length;
      const successRate = successCount / window.length;

      // Map EvasionState to matrix column index (0x01→0, 0x02→1, 0x03→2)
      const stateIndex = (state as number) - 1;

      if (successRate > SUCCESS_THRESHOLD) {
        // Apply positive gradient step to all rows' column for this state (REQ 5.6)
        for (let rowIndex = 0; rowIndex < 3; rowIndex++) {
          matrix[rowIndex][stateIndex] += GRADIENT_STEP;
        }
        updated = true;
      } else if (successRate < FAILURE_THRESHOLD) {
        // Apply negative gradient step (clamped to 0) to all rows' column (REQ 5.7)
        for (let rowIndex = 0; rowIndex < 3; rowIndex++) {
          matrix[rowIndex][stateIndex] = Math.max(0, matrix[rowIndex][stateIndex] - GRADIENT_STEP);
        }
        updated = true;
      }
    }

    if (updated) {
      // REQ 5.8, 8.6: renormalize via MarkovFSM to enforce stochastic + ergodicity constraints
      this.markovFSM.setTransitionMatrix(matrix);
      this.lastGradientUpdateAt = Date.now();
    }
  }

  // -------------------------------------------------------------------------
  // getState
  // -------------------------------------------------------------------------

  /**
   * Returns the current evaluator state for the monitor popup.
   * REQ 5.10, 6.1, 6.2, 6.7
   */
  getState(): EvaluatorState {
    const perStateStats: Record<EvasionState, StateStats> = {
      [EVASION_STATE.SPLIT]:    this._computeStats(EVASION_STATE.SPLIT),
      [EVASION_STATE.DISORDER]: this._computeStats(EVASION_STATE.DISORDER),
      [EVASION_STATE.CHAFF]:    this._computeStats(EVASION_STATE.CHAFF),
    };

    return {
      active: this.active,
      lastGradientUpdateAt: this.lastGradientUpdateAt,
      perStateStats,
    };
  }

  // -------------------------------------------------------------------------
  // reset
  // -------------------------------------------------------------------------

  /**
   * Clears all recorded outcomes and resets the TransitionMatrix to the
   * uniform distribution.
   *
   * REQ 6.4, 6.5
   */
  reset(): void {
    // Clear all rolling windows
    this.windows[EVASION_STATE.SPLIT]    = [];
    this.windows[EVASION_STATE.DISORDER] = [];
    this.windows[EVASION_STATE.CHAFF]    = [];

    // Reset TransitionMatrix to uniform distribution (REQ 6.5)
    this.markovFSM.setTransitionMatrix(DEFAULT_TRANSITION_MATRIX);

    // Clear the rate-limit timestamp
    this.lastGradientUpdateAt = null;
  }

  // -------------------------------------------------------------------------
  // toggle
  // -------------------------------------------------------------------------

  /**
   * Toggles between active and paused states.
   * Outcome recording continues when paused; only gradient updates are suspended.
   *
   * REQ 6.9
   */
  toggle(): boolean {
    this.active = !this.active;
    return this.active;
  }

  // -------------------------------------------------------------------------
  // isActive
  // -------------------------------------------------------------------------

  /**
   * Returns true if gradient updates are currently active (not paused).
   * REQ 6.7
   */
  isActive(): boolean {
    return this.active;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Computes the StateStats for a given EvasionState from its rolling window.
   */
  private _computeStats(state: EvasionState): StateStats {
    const window = this.windows[state];
    const totalOutcomes = window.length;
    const successCount = window.filter(o => o.result === 'success').length;
    const successRate = totalOutcomes > 0 ? successCount / totalOutcomes : 0;

    return {
      successRate,
      totalOutcomes,
      successCount,
    };
  }
}

// ---------------------------------------------------------------------------
// Singleton factory
// ---------------------------------------------------------------------------

let _instance: StrategyEvaluator | null = null;

/**
 * Returns the singleton StrategyEvaluator instance.
 * Throws if the instance has not been initialized via resetStrategyEvaluator().
 */
export function getStrategyEvaluator(): StrategyEvaluator {
  if (!_instance) {
    throw new Error(
      '[PPO] StrategyEvaluator singleton is not initialized. ' +
      'Call resetStrategyEvaluator(instance) before getStrategyEvaluator().',
    );
  }
  return _instance;
}

/**
 * Sets (or clears) the singleton StrategyEvaluator instance.
 *
 * Pass a `StrategyEvaluator` instance to initialize, or `null` to reset
 * (useful for testing).
 */
export function resetStrategyEvaluator(instance: StrategyEvaluator | null): void {
  _instance = instance;
}
