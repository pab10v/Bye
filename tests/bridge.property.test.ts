/**
 * Propiedad 12: Ciclo de vida del Memory Bridge sin fugas
 *
 * Valida: Requisitos 3.1, 3.3
 */
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { createWasmBridge } from '../src/bridge.js';
import { EVASION_STATE } from '../src/types.js';

describe('Propiedad 12: Ciclo de vida del Memory Bridge sin fugas', () => {
  it('para toda secuencia alloc→write→process→read→free, la memoria retorna al nivel previo', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 65536 }), { minLength: 1, maxLength: 20 }),
        (sizes) => {
          const bridge = createWasmBridge();
          const initialMemory = bridge.getMemoryUsageBytes();

          for (const size of sizes) {
            const data = new Uint8Array(size).fill(0xAB);
            const ptr = bridge.allocateBuffer(size);
            bridge.writeBuffer(ptr, data);
            const state = EVASION_STATE.SPLIT;
            const resultPtr = bridge.processBytes(ptr, size, state);
            bridge.readBuffer(resultPtr, size);
            bridge.freeBuffer(ptr);
            bridge.freeBuffer(resultPtr);
          }

          const finalMemory = bridge.getMemoryUsageBytes();
          return finalMemory === initialMemory;
        }
      ),
      { numRuns: 100 }
    );
  });
});
