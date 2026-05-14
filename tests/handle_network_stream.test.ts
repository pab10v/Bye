/**
 * Unit tests for handleNetworkStream — Task 10.1 + Task 10.4
 *
 * Requirements: 1.1, 1.2, 1.3, 11.1, 12.1, 12.3, 12.5
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  handleNetworkStream,
  activeRequests,
  getBypassManager,
  getWasmInstance,
  _coldStartQueue,
  degradedMode,
} from '../src/background.js';
import { createBypassManager } from '../src/bypass_manager.js';

// ---------------------------------------------------------------------------
// Helpers: build in-memory ReadableStream / WritableStream pairs
// ---------------------------------------------------------------------------

/** Creates a ReadableStream that emits the given chunks in order. */
function makeReadable(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index++]);
      } else {
        controller.close();
      }
    },
  });
}

/** Creates a WritableStream that collects all written chunks. */
function makeWritable(): { stream: WritableStream<Uint8Array>; chunks: Uint8Array[] } {
  const chunks: Uint8Array[] = [];
  const stream = new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk);
    },
  });
  return { stream, chunks };
}

// ---------------------------------------------------------------------------
// Reset module state between tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  // Clear the cold-start queue so tests don't interfere with each other
  _coldStartQueue.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('handleNetworkStream (Task 10.1)', () => {
  // -------------------------------------------------------------------------
  // Bypass path (REQ 1.2, 1.3)
  // -------------------------------------------------------------------------
  describe('bypass path', () => {
    it('pipes chunks directly without obfuscation when URL is in bypass list', async () => {
      // Add a bypass rule for the test URL
      const bm = getBypassManager();
      bm.addRule('bypass.example.com');

      const input = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
      const readable = makeReadable(input);
      const { stream: writable, chunks } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://bypass.example.com/path');

      // Output must be identical to input (no obfuscation)
      expect(chunks).toHaveLength(2);
      expect(chunks[0]).toEqual(input[0]);
      expect(chunks[1]).toEqual(input[1]);

      // Clean up
      bm.removeRule('bypass.example.com');
    });

    it('does NOT bypass URLs that are not in the bypass list', async () => {
      const input = [new Uint8Array([10, 20, 30])];
      const readable = makeReadable(input);
      const { stream: writable, chunks } = makeWritable();

      // Use a URL that is definitely not in the default bypass list
      await handleNetworkStream(readable, writable, 'https://obfuscate.example.com');

      // The bridge in test mode returns the same bytes (identity transform),
      // so the output should still equal the input — but the path went through Wasm
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toEqual(input[0]);
    });
  });

  // -------------------------------------------------------------------------
  // activeRequests counter (REQ 12.1)
  // -------------------------------------------------------------------------
  describe('activeRequests counter', () => {
    it('decrements activeRequests to 0 after a successful stream', async () => {
      const readable = makeReadable([new Uint8Array([1, 2, 3])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      // After completion the counter must be back to its pre-call value
      // (we can't easily read the mid-flight value, but we can verify it
      //  returns to 0 assuming no other concurrent calls)
      expect(activeRequests).toBe(0);
    });

    it('decrements activeRequests even when an error occurs mid-stream', async () => {
      // Create a readable that throws after the first chunk
      let callCount = 0;
      const errorReadable = new ReadableStream<Uint8Array>({
        pull(controller) {
          callCount++;
          if (callCount === 1) {
            controller.enqueue(new Uint8Array([1, 2, 3]));
          } else {
            controller.error(new Error('simulated stream error'));
          }
        },
      });

      const { stream: writable } = makeWritable();

      await expect(
        handleNetworkStream(errorReadable, writable, 'https://example.com'),
      ).rejects.toThrow('simulated stream error');

      // Counter must still be decremented in the finally block
      expect(activeRequests).toBe(0);
    });

    it('handles multiple concurrent streams and returns counter to 0', async () => {
      const makeStream = () => {
        const readable = makeReadable([new Uint8Array([1, 2, 3])]);
        const { stream: writable } = makeWritable();
        return { readable, writable };
      };

      const { readable: r1, writable: w1 } = makeStream();
      const { readable: r2, writable: w2 } = makeStream();
      const { readable: r3, writable: w3 } = makeStream();

      await Promise.all([
        handleNetworkStream(r1, w1, 'https://example.com'),
        handleNetworkStream(r2, w2, 'https://example.com'),
        handleNetworkStream(r3, w3, 'https://example.com'),
      ]);

      expect(activeRequests).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Stream processing (REQ 1.1)
  // -------------------------------------------------------------------------
  describe('stream processing', () => {
    it('processes all chunks from the readable stream', async () => {
      const chunks = [
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6]),
        new Uint8Array([7, 8, 9]),
      ];
      const readable = makeReadable(chunks);
      const { stream: writable, chunks: output } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      // All 3 chunks must have been written to the writable
      expect(output).toHaveLength(3);
    });

    it('handles an empty stream (no chunks) without error', async () => {
      const readable = makeReadable([]);
      const { stream: writable, chunks: output } = makeWritable();

      await expect(
        handleNetworkStream(readable, writable, 'https://example.com'),
      ).resolves.toBeUndefined();

      expect(output).toHaveLength(0);
    });

    it('output bytes equal input bytes (identity bridge in test mode)', async () => {
      const input = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const readable = makeReadable([input]);
      const { stream: writable, chunks: output } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      expect(output[0]).toEqual(input);
    });
  });

  // -------------------------------------------------------------------------
  // Latency warning (REQ 12.5)
  // -------------------------------------------------------------------------
  describe('latency warning', () => {
    it('logs a warning and sends the original chunk when latency exceeds 15ms', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // Monkey-patch performance.now to simulate slow processing
      let callCount = 0;
      vi.spyOn(performance, 'now').mockImplementation(() => {
        callCount++;
        // First call (t0): return 0; second call (elapsed): return 20 (> 15ms)
        return callCount % 2 === 1 ? 0 : 20;
      });

      const input = new Uint8Array([1, 2, 3]);
      const readable = makeReadable([input]);
      const { stream: writable, chunks: output } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      // Warning must have been logged
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('exceeds'),
        expect.any(Object),
      );

      // The original (unprocessed) chunk must have been sent
      expect(output[0]).toEqual(input);
    });

    it('does NOT log a warning when latency is within 15ms', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // performance.now returns real values (fast processing in test mode)
      const input = new Uint8Array([1, 2, 3]);
      const readable = makeReadable([input]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      // No latency warning should have been emitted
      const latencyWarnings = warnSpy.mock.calls.filter(
        (args) => typeof args[0] === 'string' && args[0].includes('exceeds'),
      );
      expect(latencyWarnings).toHaveLength(0);
    });
  });
});

// ---------------------------------------------------------------------------
// Task 10.4 — Intercepción pipeline: bypass, activeRequests y modo degradado
// REQ 1.2, 11.1, 12.3
// ---------------------------------------------------------------------------

describe('handleNetworkStream — pipeline intercepción (Task 10.4)', () => {
  // -------------------------------------------------------------------------
  // REQ 1.2 — Solicitudes en bypass list no pasan por el motor Wasm
  // -------------------------------------------------------------------------
  describe('bypass list omite el motor Wasm (REQ 1.2)', () => {
    it('no invoca bridge.processBytes cuando la URL está en la bypass list', async () => {
      // Obtener la instancia del bridge y espiar processBytes
      const bridge = await getWasmInstance();
      const processBytesSpy = vi.spyOn(bridge, 'processBytes');

      // Registrar la regla de bypass
      const bm = getBypassManager();
      bm.addRule('wasm-bypass.test');

      const readable = makeReadable([new Uint8Array([1, 2, 3])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://wasm-bypass.test/path');

      // processBytes nunca debe haberse llamado
      expect(processBytesSpy).not.toHaveBeenCalled();

      // Limpiar
      bm.removeRule('wasm-bypass.test');
    });

    it('invoca bridge.processBytes cuando la URL NO está en la bypass list', async () => {
      const bridge = await getWasmInstance();
      const processBytesSpy = vi.spyOn(bridge, 'processBytes');

      const readable = makeReadable([new Uint8Array([10, 20, 30])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://no-bypass.example.com');

      // processBytes debe haberse llamado exactamente una vez (un chunk)
      expect(processBytesSpy).toHaveBeenCalledTimes(1);
    });

    it('los bytes de salida son idénticos a los de entrada en la ruta de bypass', async () => {
      const bm = getBypassManager();
      bm.addRule('passthrough.test');

      const input = [new Uint8Array([0xaa, 0xbb, 0xcc]), new Uint8Array([0x11, 0x22])];
      const readable = makeReadable(input);
      const { stream: writable, chunks: output } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://passthrough.test/resource');

      expect(output).toHaveLength(2);
      expect(output[0]).toEqual(input[0]);
      expect(output[1]).toEqual(input[1]);

      bm.removeRule('passthrough.test');
    });
  });

  // -------------------------------------------------------------------------
  // REQ 11.1 — activeRequests se decrementa correctamente
  // -------------------------------------------------------------------------
  describe('activeRequests se decrementa correctamente (REQ 11.1)', () => {
    it('activeRequests vuelve a 0 tras completar una solicitud exitosa', async () => {
      const readable = makeReadable([new Uint8Array([1, 2, 3])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      expect(activeRequests).toBe(0);
    });

    it('activeRequests vuelve a 0 incluso cuando el stream lanza un error', async () => {
      let calls = 0;
      const errorReadable = new ReadableStream<Uint8Array>({
        pull(controller) {
          calls++;
          if (calls === 1) {
            controller.enqueue(new Uint8Array([1]));
          } else {
            controller.error(new Error('error de stream simulado'));
          }
        },
      });

      const { stream: writable } = makeWritable();

      await expect(
        handleNetworkStream(errorReadable, writable, 'https://example.com'),
      ).rejects.toThrow('error de stream simulado');

      // El bloque finally debe haber decrementado el contador
      expect(activeRequests).toBe(0);
    });

    it('activeRequests vuelve a 0 tras completar una solicitud en ruta de bypass', async () => {
      const bm = getBypassManager();
      bm.addRule('counter-bypass.test');

      const readable = makeReadable([new Uint8Array([5, 6, 7])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://counter-bypass.test');

      expect(activeRequests).toBe(0);

      bm.removeRule('counter-bypass.test');
    });
  });

  // -------------------------------------------------------------------------
  // REQ 12.3 — Modo degradado se activa al recibir MEMORY_LIMIT_EXCEEDED
  // -------------------------------------------------------------------------
  describe('modo degradado se activa con MEMORY_LIMIT_EXCEEDED (REQ 12.3)', () => {
    it('activa degradedMode cuando processBytes lanza MEMORY_LIMIT_EXCEEDED', async () => {
      const bridge = await getWasmInstance();

      // Hacer que processBytes lance MEMORY_LIMIT_EXCEEDED en la primera llamada
      vi.spyOn(bridge, 'processBytes').mockImplementationOnce(() => {
        throw new Error('MEMORY_LIMIT_EXCEEDED');
      });

      const input = new Uint8Array([1, 2, 3]);
      const readable = makeReadable([input]);
      const { stream: writable, chunks: output } = makeWritable();

      // La solicitud debe completarse sin lanzar (el error es capturado internamente)
      await handleNetworkStream(readable, writable, 'https://example.com');

      // degradedMode debe haberse activado
      expect(degradedMode).toBe(true);

      // El chunk original debe haberse enviado sin modificar
      expect(output).toHaveLength(1);
      expect(output[0]).toEqual(input);

      // Resetear degradedMode ejecutando otra solicitud (la ruta degradada llama
      // _checkMemoryAndRecover que, sin performance.memory, pone degradedMode = false)
      const r2 = makeReadable([new Uint8Array([0])]);
      const { stream: w2 } = makeWritable();
      await handleNetworkStream(r2, w2, 'https://example.com');
    });

    it('en modo degradado los chunks se pasan sin invocar processBytes', async () => {
      const bridge = await getWasmInstance();

      // Activar modo degradado forzando MEMORY_LIMIT_EXCEEDED
      vi.spyOn(bridge, 'processBytes').mockImplementationOnce(() => {
        throw new Error('MEMORY_LIMIT_EXCEEDED');
      });

      // Primera solicitud: activa degradedMode
      const r1 = makeReadable([new Uint8Array([1])]);
      const { stream: w1 } = makeWritable();
      await handleNetworkStream(r1, w1, 'https://example.com');
      expect(degradedMode).toBe(true);

      // Segunda solicitud: debe ir por la ruta degradada sin llamar processBytes
      const processBytesSpy = vi.spyOn(bridge, 'processBytes');
      const input = new Uint8Array([0xde, 0xad]);
      const r2 = makeReadable([input]);
      const { stream: w2, chunks: output2 } = makeWritable();
      await handleNetworkStream(r2, w2, 'https://example.com');

      // processBytes no debe haberse llamado en la ruta degradada
      expect(processBytesSpy).not.toHaveBeenCalled();

      // Los bytes originales deben haberse enviado
      expect(output2[0]).toEqual(input);
    });

    it('activeRequests vuelve a 0 tras una solicitud que activa el modo degradado', async () => {
      const bridge = await getWasmInstance();

      vi.spyOn(bridge, 'processBytes').mockImplementationOnce(() => {
        throw new Error('MEMORY_LIMIT_EXCEEDED');
      });

      const readable = makeReadable([new Uint8Array([9, 8, 7])]);
      const { stream: writable } = makeWritable();

      await handleNetworkStream(readable, writable, 'https://example.com');

      expect(activeRequests).toBe(0);

      // Resetear degradedMode
      const r2 = makeReadable([new Uint8Array([0])]);
      const { stream: w2 } = makeWritable();
      await handleNetworkStream(r2, w2, 'https://example.com');
    });
  });
});

