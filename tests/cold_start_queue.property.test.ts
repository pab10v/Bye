/**
 * Propiedad 13: Resiliencia de la cola durante Cold Start
 *
 * Para todo N ≤ 50: todas las solicitudes son encoladas y procesadas al completar init.
 * Para todo N > 50: las primeras 50 se encolan y las adicionales reciben COLD_START_BYPASS;
 * ninguna solicitud es descartada.
 *
 * Valida: Requisitos 2.3, 2.4, 2.5
 */
import { describe, it, expect, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import {
  enqueueOrProcess,
  drainQueue,
  _coldStartQueue,
  COLD_START_QUEUE_MAX,
} from '../src/background.js';
import { createWasmBridge } from '../src/bridge.js';
import { COLD_START_BYPASS } from '../src/types.js';

describe('Propiedad 13: Resiliencia de la cola durante Cold Start', () => {
  beforeEach(() => {
    // Limpiar la cola antes de cada test
    _coldStartQueue.length = 0;
  });

  it(
    'para todo N en [1, 200]: ninguna solicitud es descartada — todas son encoladas o reciben COLD_START_BYPASS',
    () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 200 }),
          (N) => {
            // Limpiar la cola al inicio de cada ejecución de la propiedad
            _coldStartQueue.length = 0;

            const promises: Promise<Uint8Array | typeof COLD_START_BYPASS>[] = [];

            // Enviar N solicitudes mientras Wasm no está listo (cola en cold start)
            for (let i = 0; i < N; i++) {
              promises.push(enqueueOrProcess(new Uint8Array([i % 256])));
            }

            // Verificar que el total de solicitudes "no descartadas" es exactamente N:
            // - Las primeras min(N, 50) están en la cola
            // - Las adicionales (N - 50 si N > 50) ya resolvieron con COLD_START_BYPASS
            const expectedQueued = Math.min(N, COLD_START_QUEUE_MAX);
            const expectedBypass = Math.max(0, N - COLD_START_QUEUE_MAX);

            // La cola debe tener exactamente min(N, 50) entradas
            if (_coldStartQueue.length !== expectedQueued) {
              return false;
            }

            // El número total de promesas debe ser N (ninguna descartada)
            if (promises.length !== N) {
              return false;
            }

            // Drenar la cola para resolver las promesas encoladas
            const bridge = createWasmBridge();
            drainQueue(bridge);

            // La cola debe estar vacía tras el drenado
            if (_coldStartQueue.length !== 0) {
              return false;
            }

            return true;
          }
        ),
        { numRuns: 200 }
      );
    }
  );

  it(
    'para todo N ≤ 50: todas las solicitudes son encoladas y procesadas al completar init',
    async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: COLD_START_QUEUE_MAX }),
          async (N) => {
            // Limpiar la cola al inicio de cada ejecución
            _coldStartQueue.length = 0;

            const promises: Promise<Uint8Array | typeof COLD_START_BYPASS>[] = [];

            // Enviar N solicitudes durante cold start
            for (let i = 0; i < N; i++) {
              promises.push(enqueueOrProcess(new Uint8Array([i % 256])));
            }

            // Todas deben estar en la cola (ninguna bypass)
            if (_coldStartQueue.length !== N) {
              return false;
            }

            // Simular que Wasm completa la inicialización y drenar la cola
            const bridge = createWasmBridge();
            drainQueue(bridge);

            // La cola debe estar vacía
            if (_coldStartQueue.length !== 0) {
              return false;
            }

            // Todas las promesas deben resolverse con Uint8Array (procesadas, no bypass)
            const results = await Promise.all(promises);
            const allProcessed = results.every((r) => r instanceof Uint8Array);

            return allProcessed;
          }
        ),
        { numRuns: 50 }
      );
    }
  );

  it(
    'para todo N > 50: las primeras 50 se encolan y las adicionales reciben COLD_START_BYPASS',
    async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: COLD_START_QUEUE_MAX + 1, max: 200 }),
          async (N) => {
            // Limpiar la cola al inicio de cada ejecución
            _coldStartQueue.length = 0;

            const promises: Promise<Uint8Array | typeof COLD_START_BYPASS>[] = [];

            // Enviar N solicitudes durante cold start
            for (let i = 0; i < N; i++) {
              promises.push(enqueueOrProcess(new Uint8Array([i % 256])));
            }

            // La cola debe tener exactamente 50 entradas
            if (_coldStartQueue.length !== COLD_START_QUEUE_MAX) {
              return false;
            }

            // Drenar la cola para resolver las primeras 50 promesas
            const bridge = createWasmBridge();
            drainQueue(bridge);

            // La cola debe estar vacía
            if (_coldStartQueue.length !== 0) {
              return false;
            }

            // Esperar todas las promesas
            const results = await Promise.all(promises);

            // Las primeras 50 deben haberse procesado como Uint8Array
            const firstFifty = results.slice(0, COLD_START_QUEUE_MAX);
            const allQueued = firstFifty.every((r) => r instanceof Uint8Array);

            // Las adicionales (índices 50..N-1) deben ser COLD_START_BYPASS
            const overflow = results.slice(COLD_START_QUEUE_MAX);
            const allBypass = overflow.every((r) => r === COLD_START_BYPASS);

            // Ninguna solicitud fue descartada: total de resultados == N
            const noneDiscarded = results.length === N;

            return allQueued && allBypass && noneDiscarded;
          }
        ),
        { numRuns: 100 }
      );
    }
  );
});
