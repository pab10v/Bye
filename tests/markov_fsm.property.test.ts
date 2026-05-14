/**
 * Propiedad 3: Validez estocástica de la TransitionMatrix de Markov
 *
 * Para toda actualización de pesos arbitraria: cada fila de la matriz
 * resultante suma 1.0 y todos los valores están en [0.0, 1.0].
 *
 * Valida: Requisitos 8.1, 8.2, 8.5
 *
 * Propiedad 10: Estado FSM siempre válido tras transición
 *
 * Para todo estado actual y toda métrica de red:
 * transition(metrics) ∈ {0x01, 0x02, 0x03}
 *
 * Valida: Requisito 8.3
 */
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { MarkovFSM } from '../src/markov_fsm.js';
import { EVASION_STATE, EvasionState, NetworkMetrics, TransitionWeights } from '../src/types.js';

/** All valid EvasionState values */
const EVASION_STATES: EvasionState[] = [
  EVASION_STATE.SPLIT,
  EVASION_STATE.DISORDER,
  EVASION_STATE.CHAFF,
];

/** Arbitrary generator for EvasionState */
const arbEvasionState = fc.constantFrom(...EVASION_STATES);

/**
 * Arbitrary generator for TransitionWeights.
 * Covers the full range of possible weight values including edge cases:
 * negative numbers, zero, values > 1, and normal probabilities.
 */
const arbTransitionWeights: fc.Arbitrary<TransitionWeights> = fc.record({
  fromState: arbEvasionState,
  toState: arbEvasionState,
  weight: fc.oneof(
    // Normal probability range
    fc.float({ min: 0.0, max: 1.0, noNaN: true }),
    // Edge cases: negative, zero, greater than 1
    fc.float({ min: -10.0, max: 10.0, noNaN: true }),
  ),
});

/** Tolerance for floating-point row sum comparison */
const EPSILON = 1e-10;

describe('Propiedad 3: Validez estocástica de la TransitionMatrix de Markov', () => {
  it('para toda actualización de pesos arbitraria: cada fila suma 1.0 y todos los valores están en [0.0, 1.0]', () => {
    fc.assert(
      fc.property(
        arbTransitionWeights,
        (weights: TransitionWeights) => {
          const fsm = new MarkovFSM();
          fsm.updateTransitionMatrix(weights);
          const matrix = fsm.getTransitionProbabilities();

          // Verify matrix dimensions
          if (matrix.length !== 3) return false;

          for (let i = 0; i < 3; i++) {
            const row = matrix[i];

            if (row.length !== 3) return false;

            // REQ 8.2: all values in [0.0, 1.0]
            for (let j = 0; j < 3; j++) {
              if (row[j] < 0.0 || row[j] > 1.0) return false;
            }

            // REQ 8.1: each row sums to 1.0
            const rowSum = row.reduce((acc, v) => acc + v, 0);
            if (Math.abs(rowSum - 1.0) > EPSILON) return false;
          }

          return true;
        }
      ),
      { numRuns: 1000 }
    );
  });

  it('para múltiples actualizaciones consecutivas: la propiedad estocástica se mantiene en todo momento', () => {
    fc.assert(
      fc.property(
        fc.array(arbTransitionWeights, { minLength: 1, maxLength: 20 }),
        (weightSequence: TransitionWeights[]) => {
          const fsm = new MarkovFSM();

          for (const weights of weightSequence) {
            fsm.updateTransitionMatrix(weights);
            const matrix = fsm.getTransitionProbabilities();

            if (matrix.length !== 3) return false;

            for (let i = 0; i < 3; i++) {
              const row = matrix[i];

              if (row.length !== 3) return false;

              // REQ 8.2: all values in [0.0, 1.0]
              for (let j = 0; j < 3; j++) {
                if (row[j] < 0.0 || row[j] > 1.0) return false;
              }

              // REQ 8.1: each row sums to 1.0
              const rowSum = row.reduce((acc, v) => acc + v, 0);
              if (Math.abs(rowSum - 1.0) > EPSILON) return false;
            }
          }

          return true;
        }
      ),
      { numRuns: 500 }
    );
  });
});

/**
 * Propiedad 10: Estado FSM siempre válido tras transición
 *
 * Para todo estado actual y toda métrica de red:
 * transition(metrics) ∈ {0x01, 0x02, 0x03}
 *
 * Valida: Requisito 8.3
 */

/** Set of valid EvasionState codes for membership checks */
const VALID_STATES = new Set<number>([0x01, 0x02, 0x03]);

/**
 * Arbitrary generator for NetworkMetrics including extreme values.
 *
 * Covers:
 *   - Normal operating range (latency 0–10000ms, bandwidth 0–1e9 bps, etc.)
 *   - Extreme finite values (very large positive/negative numbers)
 *   - Special IEEE 754 values: Infinity, -Infinity, NaN, -0
 *   - Boundary values: 0, 1, -1
 *   - dpiDetectionScore both below and above the 0.7 threshold that triggers
 *     the SPLIT bias in the transition logic
 */
const arbNetworkMetrics: fc.Arbitrary<NetworkMetrics> = fc.record({
  latencyMs: fc.oneof(
    fc.float({ noNaN: false }),                          // any float including NaN/Inf
    fc.constantFrom(0, -0, 1, -1, Infinity, -Infinity, Number.MAX_VALUE, Number.MIN_VALUE),
  ),
  bandwidthBps: fc.oneof(
    fc.float({ noNaN: false }),
    fc.constantFrom(0, -0, 1, -1, Infinity, -Infinity, Number.MAX_VALUE, Number.MIN_VALUE),
  ),
  packetLossRate: fc.oneof(
    fc.float({ noNaN: false }),
    fc.constantFrom(0, -0, 0.5, 1, -1, Infinity, -Infinity, NaN),
  ),
  dpiDetectionScore: fc.oneof(
    // Normal range [0.0, 1.0]
    fc.float({ min: 0.0, max: 1.0, noNaN: true }),
    // Values that cross the 0.7 threshold
    fc.constantFrom(0.0, 0.5, 0.7, 0.700001, 0.9, 1.0),
    // Extreme / out-of-range values
    fc.float({ noNaN: false }),
    fc.constantFrom(-1, Infinity, -Infinity, NaN, Number.MAX_VALUE),
  ),
});

describe('Propiedad 10: Estado FSM siempre válido tras transición', () => {
  /**
   * **Validates: Requirements 8.3**
   *
   * For every initial state and every NetworkMetrics (including extreme values):
   *   transition(metrics) ∈ {0x01, 0x02, 0x03}
   */
  it('para todo estado inicial y toda métrica de red: transition(metrics) ∈ {0x01, 0x02, 0x03}', () => {
    fc.assert(
      fc.property(
        arbEvasionState,
        arbNetworkMetrics,
        (initialState: EvasionState, metrics: NetworkMetrics) => {
          const fsm = new MarkovFSM(initialState);
          const nextState = fsm.transition(metrics);

          // The returned state must be one of the three valid EvasionState codes
          return VALID_STATES.has(nextState);
        }
      ),
      { numRuns: 1000 }
    );
  });

  it('para múltiples transiciones consecutivas con métricas extremas: el estado siempre es válido', () => {
    fc.assert(
      fc.property(
        arbEvasionState,
        fc.array(arbNetworkMetrics, { minLength: 1, maxLength: 50 }),
        (initialState: EvasionState, metricsSequence: NetworkMetrics[]) => {
          const fsm = new MarkovFSM(initialState);

          for (const metrics of metricsSequence) {
            const nextState = fsm.transition(metrics);

            if (!VALID_STATES.has(nextState)) {
              return false;
            }
          }

          return true;
        }
      ),
      { numRuns: 500 }
    );
  });

  it('con dpiDetectionScore > 0.7: el estado resultante sigue siendo válido (bias hacia SPLIT)', () => {
    fc.assert(
      fc.property(
        arbEvasionState,
        fc.record({
          latencyMs: fc.float({ min: 0, max: 10000, noNaN: true }),
          bandwidthBps: fc.float({ min: 0, max: 1e9, noNaN: true }),
          packetLossRate: fc.float({ min: 0, max: 1, noNaN: true }),
          // Force dpiDetectionScore above the 0.7 threshold
          // Use Math.fround to ensure 32-bit float compatibility required by fc.float
          dpiDetectionScore: fc.float({ min: Math.fround(0.700001), max: 1.0, noNaN: true }),
        }),
        (initialState: EvasionState, metrics: NetworkMetrics) => {
          const fsm = new MarkovFSM(initialState);
          const nextState = fsm.transition(metrics);

          return VALID_STATES.has(nextState);
        }
      ),
      { numRuns: 500 }
    );
  });
});
