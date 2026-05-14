/**
 * Unit tests for StrategyEvaluator
 *
 * Covers:
 *   - `success` recorded for clean connection (no failure, latency below baseline + 500)
 *   - `failure` recorded for latency >= 500 ms above baseline
 *   - No gradient update when paused
 *   - No gradient update during FORCE_TACTIC override
 *   - No gradient update when mesh `connected` + recent telemetry (< 60 s)
 *   - `reset()` produces uniform matrix in FSM
 *   - Cooldown prevents updates more frequent than 30 s
 *
 * Requirements: 5.1, 5.2, 5.3, 5.9, 6.4, 8.7, 8.8
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  StrategyEvaluator,
  GRADIENT_STEP,
  MIN_OUTCOMES_FOR_UPDATE,
  UPDATE_COOLDOWN_MS,
  WINDOW_SIZE,
} from '../src/strategy_evaluator.js';
import { MarkovFSM } from '../src/markov_fsm.js';
import { MeshNode } from '../src/mesh_node.js';
import { EVASION_STATE, DEFAULT_TRANSITION_MATRIX } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EPSILON = 1e-9;

/** Verifies that a 3x3 matrix satisfies the stochastic property */
function assertStochasticMatrix(matrix: number[][]): void {
  expect(matrix.length).toBe(3);
  for (let i = 0; i < 3; i++) {
    expect(matrix[i].length).toBe(3);
    for (let j = 0; j < 3; j++) {
      expect(matrix[i][j]).toBeGreaterThanOrEqual(0.0);
      expect(matrix[i][j]).toBeLessThanOrEqual(1.0);
    }
    const rowSum = matrix[i].reduce((acc, v) => acc + v, 0);
    expect(Math.abs(rowSum - 1.0)).toBeLessThan(EPSILON);
  }
}

/** Checks that a matrix is approximately equal to the uniform distribution */
function assertUniformMatrix(matrix: number[][]): void {
  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 3; j++) {
      expect(matrix[i][j]).toBeCloseTo(1 / 3, 8);
    }
  }
}

/**
 * Creates a StrategyEvaluator with injectable dependencies.
 * By default: active=true, no manual override, mesh standalone, telemetry age = Infinity.
 */
function makeEvaluator(opts: {
  enabled?: boolean;
  manualOverrideActive?: () => boolean;
  meshMode?: 'connected' | 'degraded' | 'standalone';
  lastMeshTelemetryAt?: () => number;
  markovFSM?: MarkovFSM;
  meshNode?: MeshNode;
} = {}): { evaluator: StrategyEvaluator; fsm: MarkovFSM; mesh: MeshNode } {
  const fsm = opts.markovFSM ?? new MarkovFSM();
  const mesh = opts.meshNode ?? new MeshNode();

  // Override getMode() if meshMode is specified
  if (opts.meshMode !== undefined) {
    vi.spyOn(mesh, 'getMode').mockReturnValue(opts.meshMode);
  }

  const evaluator = new StrategyEvaluator(
    fsm,
    mesh,
    { enabled: opts.enabled ?? true },
    opts.manualOverrideActive ?? (() => false),
    opts.lastMeshTelemetryAt ?? (() => 0), // very old telemetry by default
  );

  return { evaluator, fsm, mesh };
}

/**
 * Records `count` success outcomes for the given state.
 * Uses latency=10, baseline=0, failed=false so they all classify as success.
 */
function recordSuccesses(
  evaluator: StrategyEvaluator,
  state: typeof EVASION_STATE[keyof typeof EVASION_STATE],
  count: number,
): void {
  for (let i = 0; i < count; i++) {
    evaluator.recordOutcome(state, 10, false, 0);
  }
}

/**
 * Records `count` failure outcomes for the given state.
 * Uses failed=true so they all classify as failure.
 */
function recordFailures(
  evaluator: StrategyEvaluator,
  state: typeof EVASION_STATE[keyof typeof EVASION_STATE],
  count: number,
): void {
  for (let i = 0; i < count; i++) {
    evaluator.recordOutcome(state, 10, true, 0);
  }
}

// ---------------------------------------------------------------------------
// Suite 1: Outcome classification (REQ 5.2, 5.3)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — outcome classification', () => {
  it('records success for clean connection (no failure, latency well below baseline + 500)', () => {
    const { evaluator } = makeEvaluator({ enabled: false }); // disabled so no gradient side-effects
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 100, false, 200);

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(1);
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(1);
    expect(state.perStateStats[EVASION_STATE.SPLIT].successRate).toBe(1.0);
  });

  it('records success when latency is exactly 499 ms above baseline', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 699, false, 200); // 699 - 200 = 499 < 500

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(1);
  });

  it('records failure when latency is exactly 500 ms above baseline (REQ 5.3)', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 700, false, 200); // 700 - 200 = 500 >= 500

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(0);
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(1);
  });

  it('records failure when latency is more than 500 ms above baseline', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 1000, false, 200); // 1000 - 200 = 800 >= 500

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(0);
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(1);
  });

  it('records failure when failed=true regardless of latency (REQ 5.3)', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, true, 0); // failed=true, low latency

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(0);
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(1);
  });

  it('records failure when both failed=true and latency spike are present', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 1000, true, 0);

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(0);
  });

  it('records outcomes independently per state', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, false, 0);    // success
    evaluator.recordOutcome(EVASION_STATE.DISORDER, 10, true, 0);  // failure
    evaluator.recordOutcome(EVASION_STATE.CHAFF, 600, false, 0);   // failure (600 >= 500)

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(1);
    expect(state.perStateStats[EVASION_STATE.DISORDER].successCount).toBe(0);
    expect(state.perStateStats[EVASION_STATE.CHAFF].successCount).toBe(0);
  });

  it('success rate is 0 when no outcomes recorded', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].successRate).toBe(0);
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Suite 2: Rolling window eviction (REQ 5.4)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — rolling window eviction', () => {
  it('window never exceeds WINDOW_SIZE (100) entries', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    const extra = 20;

    for (let i = 0; i < WINDOW_SIZE + extra; i++) {
      evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, false, 0);
    }

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(WINDOW_SIZE);
  });

  it('oldest entries are evicted first (FIFO)', () => {
    const { evaluator } = makeEvaluator({ enabled: false });

    // Fill window with failures
    for (let i = 0; i < WINDOW_SIZE; i++) {
      evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, true, 0); // failure
    }

    // Add one success — it should push out the oldest failure
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, false, 0); // success

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(WINDOW_SIZE);
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: Gradient update guards (REQ 5.9, 8.7, 8.8)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — gradient update guards', () => {
  it('no gradient update when paused (active=false)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: false });
    const matrixBefore = fsm.getTransitionProbabilities();

    // Record enough successes to trigger a gradient update if active
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });

  it('toggle() enables gradient updates; subsequent outcomes trigger update', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: false });

    // Enable the evaluator
    const newActive = evaluator.toggle();
    expect(newActive).toBe(true);
    expect(evaluator.isActive()).toBe(true);

    const matrixBefore = fsm.getTransitionProbabilities();

    // Record enough successes to trigger a gradient update
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    // The SPLIT column (index 0) should have increased
    const changed = matrixAfter[0][0] !== matrixBefore[0][0] ||
                    matrixAfter[1][0] !== matrixBefore[1][0] ||
                    matrixAfter[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('no gradient update during FORCE_TACTIC override (REQ 8.8)', () => {
    let overrideActive = true;
    const { evaluator, fsm } = makeEvaluator({
      enabled: true,
      manualOverrideActive: () => overrideActive,
    });

    const matrixBefore = fsm.getTransitionProbabilities();

    // Record enough successes to trigger a gradient update if override were inactive
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }

    // Deactivate override — next outcome should trigger update
    overrideActive = false;
    evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, false, 0);

    const matrixFinal = fsm.getTransitionProbabilities();
    const changed = matrixFinal[0][0] !== matrixBefore[0][0] ||
                    matrixFinal[1][0] !== matrixBefore[1][0] ||
                    matrixFinal[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('no gradient update when mesh connected + recent telemetry (< 60 s) (REQ 8.7)', () => {
    const now = Date.now();
    const { evaluator, fsm } = makeEvaluator({
      enabled: true,
      meshMode: 'connected',
      lastMeshTelemetryAt: () => now - 30_000, // 30 s ago — within 60 s window
    });

    const matrixBefore = fsm.getTransitionProbabilities();

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });

  it('gradient update proceeds when mesh connected but telemetry is stale (>= 60 s)', () => {
    const now = Date.now();
    const { evaluator, fsm } = makeEvaluator({
      enabled: true,
      meshMode: 'connected',
      lastMeshTelemetryAt: () => now - 61_000, // 61 s ago — outside deferral window
    });

    const matrixBefore = fsm.getTransitionProbabilities();

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    const changed = matrixAfter[0][0] !== matrixBefore[0][0] ||
                    matrixAfter[1][0] !== matrixBefore[1][0] ||
                    matrixAfter[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('gradient update proceeds when mesh is standalone (not connected)', () => {
    const now = Date.now();
    const { evaluator, fsm } = makeEvaluator({
      enabled: true,
      meshMode: 'standalone',
      lastMeshTelemetryAt: () => now - 1_000, // very recent, but mesh not connected
    });

    const matrixBefore = fsm.getTransitionProbabilities();

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    const matrixAfter = fsm.getTransitionProbabilities();
    const changed = matrixAfter[0][0] !== matrixBefore[0][0] ||
                    matrixAfter[1][0] !== matrixBefore[1][0] ||
                    matrixAfter[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('no gradient update when fewer than MIN_OUTCOMES_FOR_UPDATE outcomes recorded', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });
    const matrixBefore = fsm.getTransitionProbabilities();

    // Record one fewer than the minimum
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE - 1);

    const matrixAfter = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Suite 4: Cooldown (REQ 5.9)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — cooldown prevents updates more frequent than 30 s', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('second gradient update is blocked within the 30 s cooldown window', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    // Trigger first gradient update
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);
    const matrixAfterFirst = fsm.getTransitionProbabilities().map(row => [...row]);

    // Advance time by less than 30 s
    vi.advanceTimersByTime(UPDATE_COOLDOWN_MS - 1000);

    // Record more outcomes — should NOT trigger another update
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 5);

    const matrixAfterSecond = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfterSecond[i][j]).toBeCloseTo(matrixAfterFirst[i][j], 10);
      }
    }
  });

  it('gradient update is allowed after the 30 s cooldown expires', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    // Trigger first gradient update
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);
    const matrixAfterFirst = fsm.getTransitionProbabilities().map(row => [...row]);

    // Advance time past the cooldown
    vi.advanceTimersByTime(UPDATE_COOLDOWN_MS + 1000);

    // Record more outcomes — should trigger another update
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 5);

    const matrixAfterSecond = fsm.getTransitionProbabilities();
    const changed = matrixAfterSecond[0][0] !== matrixAfterFirst[0][0] ||
                    matrixAfterSecond[1][0] !== matrixAfterFirst[1][0] ||
                    matrixAfterSecond[2][0] !== matrixAfterFirst[2][0];
    expect(changed).toBe(true);
  });

  it('lastGradientUpdateAt is set after first update and null before any update', () => {
    const { evaluator } = makeEvaluator({ enabled: true });

    expect(evaluator.getState().lastGradientUpdateAt).toBeNull();

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, MIN_OUTCOMES_FOR_UPDATE + 5);

    expect(evaluator.getState().lastGradientUpdateAt).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Suite 5: Gradient direction (REQ 5.6, 5.7)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — gradient direction', () => {
  it('positive gradient step applied when success rate > 0.7 (REQ 5.6)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });
    const matrixBefore = fsm.getTransitionProbabilities();

    // Record 15 successes for SPLIT — success rate = 1.0 > 0.7
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 15);

    const matrixAfter = fsm.getTransitionProbabilities();

    // SPLIT column (index 0) should have increased in all rows
    // (after normalization the absolute values may differ, but the column
    //  should be larger relative to the uniform baseline)
    // We verify the matrix changed and is still stochastic
    assertStochasticMatrix(matrixAfter);

    const changed = matrixAfter[0][0] !== matrixBefore[0][0] ||
                    matrixAfter[1][0] !== matrixBefore[1][0] ||
                    matrixAfter[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('negative gradient step applied when success rate < 0.3 (REQ 5.7)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });
    const matrixBefore = fsm.getTransitionProbabilities();

    // Record 15 failures for SPLIT — success rate = 0.0 < 0.3
    recordFailures(evaluator, EVASION_STATE.SPLIT, 15);

    const matrixAfter = fsm.getTransitionProbabilities();

    assertStochasticMatrix(matrixAfter);

    const changed = matrixAfter[0][0] !== matrixBefore[0][0] ||
                    matrixAfter[1][0] !== matrixBefore[1][0] ||
                    matrixAfter[2][0] !== matrixBefore[2][0];
    expect(changed).toBe(true);
  });

  it('no gradient update when success rate is between 0.3 and 0.7 (neutral zone)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });
    const matrixBefore = fsm.getTransitionProbabilities();

    // Record 10 outcomes: 5 success, 5 failure → rate = 0.5 (neutral)
    for (let i = 0; i < 5; i++) {
      evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, false, 0); // success
      evaluator.recordOutcome(EVASION_STATE.SPLIT, 10, true, 0);  // failure
    }

    const matrixAfter = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });

  it('matrix remains stochastic after gradient update (REQ 5.8)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 15);

    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('matrix cells remain >= 0.01 after negative gradient update (ergodicity, REQ 8.6)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    recordFailures(evaluator, EVASION_STATE.SPLIT, 15);

    const matrix = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrix[i][j]).toBeGreaterThanOrEqual(0.01);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Suite 6: reset() (REQ 6.4, 6.5)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — reset()', () => {
  it('reset() clears all recorded outcomes', () => {
    const { evaluator } = makeEvaluator({ enabled: false });

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 10);
    recordFailures(evaluator, EVASION_STATE.DISORDER, 5);

    evaluator.reset();

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(0);
    expect(state.perStateStats[EVASION_STATE.DISORDER].totalOutcomes).toBe(0);
    expect(state.perStateStats[EVASION_STATE.CHAFF].totalOutcomes).toBe(0);
  });

  it('reset() produces uniform matrix in FSM (REQ 6.4, 6.5)', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    // Apply some gradient updates to skew the matrix
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 15);

    // Verify matrix was changed
    const matrixSkewed = fsm.getTransitionProbabilities();
    const isUniform = matrixSkewed.every(row =>
      row.every(cell => Math.abs(cell - 1 / 3) < 0.001)
    );
    expect(isUniform).toBe(false);

    // Reset
    evaluator.reset();

    // Matrix should now be uniform
    assertUniformMatrix(fsm.getTransitionProbabilities());
  });

  it('reset() sets lastGradientUpdateAt to null', () => {
    const { evaluator } = makeEvaluator({ enabled: true });

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 15);
    expect(evaluator.getState().lastGradientUpdateAt).not.toBeNull();

    evaluator.reset();
    expect(evaluator.getState().lastGradientUpdateAt).toBeNull();
  });

  it('reset() is idempotent — calling it twice produces the same result', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: true });

    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 15);

    evaluator.reset();
    const matrixAfterFirst = fsm.getTransitionProbabilities();

    evaluator.reset();
    const matrixAfterSecond = fsm.getTransitionProbabilities();

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfterSecond[i][j]).toBeCloseTo(matrixAfterFirst[i][j], 10);
      }
    }
  });

  it('reset() on a fresh evaluator (no outcomes) still produces uniform matrix', () => {
    const { evaluator, fsm } = makeEvaluator({ enabled: false });

    evaluator.reset();

    assertUniformMatrix(fsm.getTransitionProbabilities());
  });
});

// ---------------------------------------------------------------------------
// Suite 7: toggle() and isActive() (REQ 6.9)
// ---------------------------------------------------------------------------

describe('StrategyEvaluator — toggle() and isActive()', () => {
  it('isActive() returns true when enabled=true at construction', () => {
    const { evaluator } = makeEvaluator({ enabled: true });
    expect(evaluator.isActive()).toBe(true);
  });

  it('isActive() returns false when enabled=false at construction', () => {
    const { evaluator } = makeEvaluator({ enabled: false });
    expect(evaluator.isActive()).toBe(false);
  });

  it('toggle() flips active state and returns new value', () => {
    const { evaluator } = makeEvaluator({ enabled: true });

    const result1 = evaluator.toggle();
    expect(result1).toBe(false);
    expect(evaluator.isActive()).toBe(false);

    const result2 = evaluator.toggle();
    expect(result2).toBe(true);
    expect(evaluator.isActive()).toBe(true);
  });

  it('outcome recording continues when paused (toggle only affects gradient updates)', () => {
    const { evaluator } = makeEvaluator({ enabled: true });

    // Pause
    evaluator.toggle();
    expect(evaluator.isActive()).toBe(false);

    // Record outcomes while paused
    recordSuccesses(evaluator, EVASION_STATE.SPLIT, 5);

    const state = evaluator.getState();
    expect(state.perStateStats[EVASION_STATE.SPLIT].totalOutcomes).toBe(5);
    expect(state.perStateStats[EVASION_STATE.SPLIT].successCount).toBe(5);
  });

  it('getState() reflects active flag correctly', () => {
    const { evaluator } = makeEvaluator({ enabled: true });

    expect(evaluator.getState().active).toBe(true);

    evaluator.toggle();
    expect(evaluator.getState().active).toBe(false);
  });
});
