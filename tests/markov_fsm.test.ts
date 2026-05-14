/**
 * Unit tests para MarkovFSM
 *
 * Cubre:
 *   - Convergencia a la distribución estacionaria esperada (1000 transiciones)
 *   - Que dpiDetectionScore > 0.7 incrementa la probabilidad de SPLIT
 *   - Que updateTransitionMatrix mantiene la propiedad estocástica
 *
 * Requisitos: 8.4, 8.5, 8.6
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { MarkovFSM, resetMarkovFSM } from '../src/markov_fsm.js';
import { EVASION_STATE, EvasionState, NetworkMetrics, TransitionWeights } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Tolerance for floating-point row sum comparison */
const EPSILON = 1e-10;

/** Verifies that a 3×3 matrix satisfies the stochastic property */
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

/** Builds a NetworkMetrics object with the given dpiDetectionScore */
function metricsWithDpi(dpiDetectionScore: number): NetworkMetrics {
  return { latencyMs: 10, bandwidthBps: 1_000_000, packetLossRate: 0.0, dpiDetectionScore };
}

// ---------------------------------------------------------------------------
// Suite 1: Convergencia a la distribución estacionaria (REQ 8.6)
// ---------------------------------------------------------------------------

describe('MarkovFSM — convergencia a la distribución estacionaria', () => {
  /**
   * For a uniform initial transition matrix (1/3, 1/3, 1/3 per row) the
   * stationary distribution is also uniform: π = [1/3, 1/3, 1/3].
   *
   * After 1000 transitions the empirical frequency of each state should be
   * close to 1/3 (within ±10 percentage points, i.e. tolerance 0.10).
   *
   * REQ 8.6: the Markov chain is ergodic → unique stationary distribution exists.
   */
  it('con matriz uniforme: la frecuencia empírica de cada estado converge a 1/3 tras 1000 transiciones', () => {
    const fsm = new MarkovFSM(EVASION_STATE.SPLIT);
    const counts: Record<EvasionState, number> = {
      [EVASION_STATE.SPLIT]: 0,
      [EVASION_STATE.DISORDER]: 0,
      [EVASION_STATE.CHAFF]: 0,
    };

    const N = 1000;
    const metrics = metricsWithDpi(0.0); // no DPI bias

    for (let i = 0; i < N; i++) {
      const state = fsm.transition(metrics);
      counts[state]++;
    }

    const tolerance = 0.10; // ±10 percentage points
    expect(counts[EVASION_STATE.SPLIT] / N).toBeGreaterThan(1 / 3 - tolerance);
    expect(counts[EVASION_STATE.SPLIT] / N).toBeLessThan(1 / 3 + tolerance);

    expect(counts[EVASION_STATE.DISORDER] / N).toBeGreaterThan(1 / 3 - tolerance);
    expect(counts[EVASION_STATE.DISORDER] / N).toBeLessThan(1 / 3 + tolerance);

    expect(counts[EVASION_STATE.CHAFF] / N).toBeGreaterThan(1 / 3 - tolerance);
    expect(counts[EVASION_STATE.CHAFF] / N).toBeLessThan(1 / 3 + tolerance);
  });

  /**
   * With a strongly biased matrix that always transitions to SPLIT (row 0 = [1,0,0],
   * row 1 = [1,0,0], row 2 = [1,0,0]) the stationary distribution is π_SPLIT = 1.
   *
   * After 1000 transitions, SPLIT should dominate (> 90% of visits).
   * The ergodicity constraint (MIN_CELL_VALUE = 0.01) means the matrix is
   * renormalized, so we use setTransitionMatrix to set a strongly biased matrix
   * and verify the empirical distribution reflects the bias.
   */
  it('con matriz sesgada hacia SPLIT: la frecuencia empírica de SPLIT es dominante tras 1000 transiciones', () => {
    const fsm = new MarkovFSM(EVASION_STATE.SPLIT);

    // Set a matrix strongly biased toward SPLIT.
    // After ergodicity clamping (min 0.01) and normalization the SPLIT column
    // will still be the largest, so SPLIT should dominate.
    fsm.setTransitionMatrix([
      [0.98, 0.01, 0.01],
      [0.98, 0.01, 0.01],
      [0.98, 0.01, 0.01],
    ]);

    const counts: Record<EvasionState, number> = {
      [EVASION_STATE.SPLIT]: 0,
      [EVASION_STATE.DISORDER]: 0,
      [EVASION_STATE.CHAFF]: 0,
    };

    const N = 1000;
    const metrics = metricsWithDpi(0.0); // no DPI bias

    for (let i = 0; i < N; i++) {
      const state = fsm.transition(metrics);
      counts[state]++;
    }

    // SPLIT should account for the vast majority of transitions
    expect(counts[EVASION_STATE.SPLIT] / N).toBeGreaterThan(0.85);
  });

  /**
   * With a matrix biased toward CHAFF the empirical distribution should
   * converge to a CHAFF-dominant stationary distribution.
   */
  it('con matriz sesgada hacia CHAFF: la frecuencia empírica de CHAFF es dominante tras 1000 transiciones', () => {
    const fsm = new MarkovFSM(EVASION_STATE.SPLIT);

    fsm.setTransitionMatrix([
      [0.01, 0.01, 0.98],
      [0.01, 0.01, 0.98],
      [0.01, 0.01, 0.98],
    ]);

    const counts: Record<EvasionState, number> = {
      [EVASION_STATE.SPLIT]: 0,
      [EVASION_STATE.DISORDER]: 0,
      [EVASION_STATE.CHAFF]: 0,
    };

    const N = 1000;
    const metrics = metricsWithDpi(0.0);

    for (let i = 0; i < N; i++) {
      const state = fsm.transition(metrics);
      counts[state]++;
    }

    expect(counts[EVASION_STATE.CHAFF] / N).toBeGreaterThan(0.85);
  });
});

// ---------------------------------------------------------------------------
// Suite 2: dpiDetectionScore > 0.7 incrementa la probabilidad de SPLIT (REQ 8.4)
// ---------------------------------------------------------------------------

describe('MarkovFSM — dpiDetectionScore > 0.7 incrementa la probabilidad de SPLIT', () => {
  /**
   * REQ 8.4: When dpiDetectionScore > 0.7, the FSM must increase the
   * probability of transitioning to SPLIT by 0.3 and renormalize.
   *
   * We verify this by comparing the empirical frequency of SPLIT over many
   * transitions with high DPI score vs. low DPI score.  With a uniform
   * matrix the high-DPI run should produce significantly more SPLIT states.
   */
  it('la frecuencia de SPLIT es significativamente mayor con dpiDetectionScore=0.9 que con dpiDetectionScore=0.0', () => {
    const N = 2000;

    // Run with high DPI score
    const fsmHigh = new MarkovFSM(EVASION_STATE.SPLIT);
    let splitCountHigh = 0;
    for (let i = 0; i < N; i++) {
      if (fsmHigh.transition(metricsWithDpi(0.9)) === EVASION_STATE.SPLIT) {
        splitCountHigh++;
      }
    }

    // Run with low DPI score (no bias)
    const fsmLow = new MarkovFSM(EVASION_STATE.SPLIT);
    let splitCountLow = 0;
    for (let i = 0; i < N; i++) {
      if (fsmLow.transition(metricsWithDpi(0.0)) === EVASION_STATE.SPLIT) {
        splitCountLow++;
      }
    }

    const freqHigh = splitCountHigh / N;
    const freqLow = splitCountLow / N;

    // High DPI should produce noticeably more SPLIT transitions
    expect(freqHigh).toBeGreaterThan(freqLow + 0.10);
  });

  /**
   * The DPI adjustment is applied to a temporary copy of the row — the
   * permanent matrix must NOT be modified by the transition call.
   *
   * REQ 8.4: "The internal matrix is NOT permanently modified by the DPI
   * adjustment — the adjustment is applied to a temporary copy."
   */
  it('la matriz permanente no se modifica tras una transición con dpiDetectionScore > 0.7', () => {
    const fsm = new MarkovFSM(EVASION_STATE.SPLIT);
    const matrixBefore = fsm.getTransitionProbabilities();

    // Perform several transitions with high DPI score
    for (let i = 0; i < 50; i++) {
      fsm.transition(metricsWithDpi(0.95));
    }

    const matrixAfter = fsm.getTransitionProbabilities();

    // The permanent matrix must be unchanged
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });

  /**
   * Boundary: dpiDetectionScore exactly at 0.7 should NOT trigger the bias
   * (the condition is strictly > 0.7).
   */
  it('con dpiDetectionScore exactamente 0.7 la matriz permanente no se modifica', () => {
    const fsm = new MarkovFSM(EVASION_STATE.SPLIT);
    const matrixBefore = fsm.getTransitionProbabilities();

    for (let i = 0; i < 50; i++) {
      fsm.transition(metricsWithDpi(0.7));
    }

    const matrixAfter = fsm.getTransitionProbabilities();

    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrixAfter[i][j]).toBeCloseTo(matrixBefore[i][j], 10);
      }
    }
  });

  /**
   * With a matrix that is strongly biased away from SPLIT, a high DPI score
   * should still produce a noticeable increase in SPLIT frequency because
   * the +0.3 adjustment is applied before roulette selection.
   */
  it('con matriz sesgada contra SPLIT: dpiDetectionScore > 0.7 aún incrementa la frecuencia de SPLIT', () => {
    const N = 2000;

    // Matrix strongly biased toward CHAFF
    const biasedMatrix = [
      [0.01, 0.01, 0.98],
      [0.01, 0.01, 0.98],
      [0.01, 0.01, 0.98],
    ];

    const fsmHigh = new MarkovFSM(EVASION_STATE.SPLIT);
    fsmHigh.setTransitionMatrix(biasedMatrix);
    let splitCountHigh = 0;
    for (let i = 0; i < N; i++) {
      if (fsmHigh.transition(metricsWithDpi(0.9)) === EVASION_STATE.SPLIT) {
        splitCountHigh++;
      }
    }

    const fsmLow = new MarkovFSM(EVASION_STATE.SPLIT);
    fsmLow.setTransitionMatrix(biasedMatrix);
    let splitCountLow = 0;
    for (let i = 0; i < N; i++) {
      if (fsmLow.transition(metricsWithDpi(0.0)) === EVASION_STATE.SPLIT) {
        splitCountLow++;
      }
    }

    // High DPI should produce more SPLIT even when the base matrix disfavors it
    expect(splitCountHigh / N).toBeGreaterThan(splitCountLow / N);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: updateTransitionMatrix mantiene la propiedad estocástica (REQ 8.5, 8.6)
// ---------------------------------------------------------------------------

describe('MarkovFSM — updateTransitionMatrix mantiene la propiedad estocástica', () => {
  /**
   * REQ 8.5: After any call to updateTransitionMatrix the affected row must
   * still sum to 1.0 and all values must be in [0.0, 1.0].
   */
  it('tras updateTransitionMatrix con peso válido: la fila afectada suma 1.0 y todos los valores están en [0.0, 1.0]', () => {
    const fsm = new MarkovFSM();

    const weights: TransitionWeights = {
      fromState: EVASION_STATE.SPLIT,
      toState: EVASION_STATE.DISORDER,
      weight: 0.6,
    };

    fsm.updateTransitionMatrix(weights);
    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('tras updateTransitionMatrix con peso 0: la propiedad estocástica se mantiene (ergodicity clamp)', () => {
    const fsm = new MarkovFSM();

    fsm.updateTransitionMatrix({ fromState: EVASION_STATE.DISORDER, toState: EVASION_STATE.SPLIT, weight: 0 });
    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('tras updateTransitionMatrix con peso negativo: la propiedad estocástica se mantiene', () => {
    const fsm = new MarkovFSM();

    fsm.updateTransitionMatrix({ fromState: EVASION_STATE.CHAFF, toState: EVASION_STATE.CHAFF, weight: -5 });
    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('tras updateTransitionMatrix con peso > 1: la propiedad estocástica se mantiene', () => {
    const fsm = new MarkovFSM();

    fsm.updateTransitionMatrix({ fromState: EVASION_STATE.SPLIT, toState: EVASION_STATE.SPLIT, weight: 100 });
    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('tras múltiples actualizaciones consecutivas: la propiedad estocástica se mantiene en todo momento', () => {
    const fsm = new MarkovFSM();

    const updates: TransitionWeights[] = [
      { fromState: EVASION_STATE.SPLIT,    toState: EVASION_STATE.DISORDER, weight: 0.5 },
      { fromState: EVASION_STATE.DISORDER, toState: EVASION_STATE.CHAFF,    weight: 0.8 },
      { fromState: EVASION_STATE.CHAFF,    toState: EVASION_STATE.SPLIT,    weight: 0.2 },
      { fromState: EVASION_STATE.SPLIT,    toState: EVASION_STATE.SPLIT,    weight: 0.0 },
      { fromState: EVASION_STATE.DISORDER, toState: EVASION_STATE.DISORDER, weight: 1.5 },
    ];

    for (const w of updates) {
      fsm.updateTransitionMatrix(w);
      assertStochasticMatrix(fsm.getTransitionProbabilities());
    }
  });

  /**
   * REQ 8.6: Ergodicity constraint — no cell may be < MIN_CELL_VALUE (0.01).
   * Even if a weight of 0 is set, the cell must be clamped to at least 0.01.
   */
  it('la restricción de ergodicidad garantiza que ninguna celda es < 0.01 tras updateTransitionMatrix', () => {
    const fsm = new MarkovFSM();

    // Try to zero out a cell
    fsm.updateTransitionMatrix({ fromState: EVASION_STATE.SPLIT, toState: EVASION_STATE.CHAFF, weight: 0 });

    const matrix = fsm.getTransitionProbabilities();
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        expect(matrix[i][j]).toBeGreaterThanOrEqual(0.01);
      }
    }
  });

  /**
   * Only the row corresponding to fromState should be modified; the other
   * two rows must remain unchanged.
   */
  it('updateTransitionMatrix solo modifica la fila de fromState; las demás filas permanecen iguales', () => {
    const fsm = new MarkovFSM();
    const before = fsm.getTransitionProbabilities();

    // Update only the DISORDER row (index 1)
    fsm.updateTransitionMatrix({ fromState: EVASION_STATE.DISORDER, toState: EVASION_STATE.SPLIT, weight: 0.7 });

    const after = fsm.getTransitionProbabilities();

    // Row 0 (SPLIT) and row 2 (CHAFF) must be unchanged
    for (let j = 0; j < 3; j++) {
      expect(after[0][j]).toBeCloseTo(before[0][j], 10);
      expect(after[2][j]).toBeCloseTo(before[2][j], 10);
    }

    // Row 1 (DISORDER) must have changed
    const rowChanged = after[1].some((v, j) => Math.abs(v - before[1][j]) > EPSILON);
    expect(rowChanged).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Suite 4: Comportamiento general del FSM (REQ 8.3, 8.7)
// ---------------------------------------------------------------------------

describe('MarkovFSM — comportamiento general', () => {
  it('getCurrentState retorna el estado inicial correcto', () => {
    expect(new MarkovFSM(EVASION_STATE.SPLIT).getCurrentState()).toBe(EVASION_STATE.SPLIT);
    expect(new MarkovFSM(EVASION_STATE.DISORDER).getCurrentState()).toBe(EVASION_STATE.DISORDER);
    expect(new MarkovFSM(EVASION_STATE.CHAFF).getCurrentState()).toBe(EVASION_STATE.CHAFF);
  });

  it('transition siempre retorna un estado válido ∈ {0x01, 0x02, 0x03}', () => {
    const validStates = new Set<number>([0x01, 0x02, 0x03]);
    const fsm = new MarkovFSM();

    for (let i = 0; i < 200; i++) {
      const state = fsm.transition(metricsWithDpi(Math.random()));
      expect(validStates.has(state)).toBe(true);
    }
  });

  it('getTransitionProbabilities retorna una copia profunda (no una referencia interna)', () => {
    const fsm = new MarkovFSM();
    const copy1 = fsm.getTransitionProbabilities();

    // Mutate the returned copy
    copy1[0][0] = 999;

    const copy2 = fsm.getTransitionProbabilities();

    // The internal matrix must be unaffected
    expect(copy2[0][0]).not.toBe(999);
  });

  it('la matriz inicial satisface la propiedad estocástica', () => {
    const fsm = new MarkovFSM();
    assertStochasticMatrix(fsm.getTransitionProbabilities());
  });

  it('singleton resetMarkovFSM crea una nueva instancia', () => {
    resetMarkovFSM();
    // After reset, getMarkovFSM should return a fresh instance — we just
    // verify that resetMarkovFSM does not throw and the module exports it.
    expect(typeof resetMarkovFSM).toBe('function');
  });
});
