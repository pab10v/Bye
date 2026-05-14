/**
 * Propiedad 5: Latencia acotada de procesamiento por paquete
 *
 * Para todo paquete de tamaño ≤ 64KB:
 *   processingTime(processBytes(ptr, len, state)) ≤ 15ms
 *
 * Usar `fast-check` con tamaños de paquete arbitrarios en [1, 65536] bytes
 * y los tres estados FSM: 0x01 (SPLIT), 0x02 (DISORDER), 0x03 (CHAFF).
 *
 * **Valida: Requisito 12.1**
 */

import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { createWasmBridge } from '../src/bridge.js';
import { EVASION_STATE, EvasionState } from '../src/types.js';

/** Maximum allowed processing latency in milliseconds (REQ 12.1). */
const MAX_LATENCY_MS = 15;

/** Maximum packet size in bytes (64 KB). */
const MAX_PACKET_SIZE = 65536;

/** All three FSM evasion states. */
const ALL_STATES: EvasionState[] = [
  EVASION_STATE.SPLIT,    // 0x01
  EVASION_STATE.DISORDER, // 0x02
  EVASION_STATE.CHAFF,    // 0x03
];

/**
 * Arbitrary generator for EvasionState — picks uniformly from the three valid states.
 */
const arbEvasionState: fc.Arbitrary<EvasionState> = fc.constantFrom(...ALL_STATES);

/**
 * Arbitrary generator for packet size in [1, 65536] bytes.
 */
const arbPacketSize: fc.Arbitrary<number> = fc.integer({ min: 1, max: MAX_PACKET_SIZE });

describe('Propiedad 5: Latencia acotada de procesamiento por paquete', () => {
  it(
    'para todo paquete ≤ 64KB y todo estado FSM: processingTime(processBytes) ≤ 15ms',
    () => {
      fc.assert(
        fc.property(
          arbPacketSize,
          arbEvasionState,
          (packetSize, state) => {
            // Create a fresh bridge per run to avoid memory accumulation
            const bridge = createWasmBridge();

            // Build a packet of the given size filled with a recognisable pattern
            const data = new Uint8Array(packetSize).fill(0xAB);

            // Allocate buffer and write the packet into Wasm linear memory
            const ptr = bridge.allocateBuffer(packetSize);
            bridge.writeBuffer(ptr, data);

            // Measure the processing time of processBytes
            const t0 = performance.now();
            const resultPtr = bridge.processBytes(ptr, packetSize, state);
            const elapsed = performance.now() - t0;

            // Read and free buffers to keep memory clean
            bridge.readBuffer(resultPtr, packetSize);
            bridge.freeBuffer(ptr);
            bridge.freeBuffer(resultPtr);

            // Property: processing time must be within the 15ms bound (REQ 12.1)
            return elapsed <= MAX_LATENCY_MS;
          },
        ),
        { numRuns: 200 },
      );
    },
  );

  it(
    'para cada estado FSM individualmente: processingTime(processBytes) ≤ 15ms con paquetes de tamaño arbitrario',
    () => {
      for (const state of ALL_STATES) {
        fc.assert(
          fc.property(
            arbPacketSize,
            (packetSize) => {
              const bridge = createWasmBridge();
              const data = new Uint8Array(packetSize).fill(0xCD);

              const ptr = bridge.allocateBuffer(packetSize);
              bridge.writeBuffer(ptr, data);

              const t0 = performance.now();
              const resultPtr = bridge.processBytes(ptr, packetSize, state);
              const elapsed = performance.now() - t0;

              bridge.readBuffer(resultPtr, packetSize);
              bridge.freeBuffer(ptr);
              bridge.freeBuffer(resultPtr);

              return elapsed <= MAX_LATENCY_MS;
            },
          ),
          { numRuns: 100 },
        );
      }
    },
  );

  it(
    'para paquetes de tamaño máximo (64KB) y todos los estados FSM: processingTime ≤ 15ms',
    () => {
      fc.assert(
        fc.property(
          arbEvasionState,
          (state) => {
            const bridge = createWasmBridge();
            const data = new Uint8Array(MAX_PACKET_SIZE).fill(0xFF);

            const ptr = bridge.allocateBuffer(MAX_PACKET_SIZE);
            bridge.writeBuffer(ptr, data);

            const t0 = performance.now();
            const resultPtr = bridge.processBytes(ptr, MAX_PACKET_SIZE, state);
            const elapsed = performance.now() - t0;

            bridge.readBuffer(resultPtr, MAX_PACKET_SIZE);
            bridge.freeBuffer(ptr);
            bridge.freeBuffer(resultPtr);

            return elapsed <= MAX_LATENCY_MS;
          },
        ),
        { numRuns: 50 },
      );
    },
  );
});
