import { describe, it, expect } from 'vitest';
import { createWasmBridge, MAX_MEMORY_BYTES } from '../src/bridge.js';
import { MEMORY_LIMIT_EXCEEDED, EVASION_STATE } from '../src/types.js';

describe('WasmNetworkBridge', () => {
  it('allocateBuffer(0) lanza MEMORY_LIMIT_EXCEEDED', () => {
    const bridge = createWasmBridge();
    expect(() => bridge.allocateBuffer(0)).toThrow(MEMORY_LIMIT_EXCEEDED);
  });

  it('allocateBuffer retorna pointer > 0 para size válido', () => {
    const bridge = createWasmBridge();
    const ptr = bridge.allocateBuffer(1024);
    expect(ptr).toBeGreaterThan(0);
    bridge.freeBuffer(ptr);
  });

  it('freeBuffer de pointer inválido no lanza error', () => {
    const bridge = createWasmBridge();
    expect(() => bridge.freeBuffer(99999)).not.toThrow();
  });

  it('readBuffer tras freeBuffer lanza error', () => {
    const bridge = createWasmBridge();
    const ptr = bridge.allocateBuffer(64);
    bridge.writeBuffer(ptr, new Uint8Array(64).fill(1));
    bridge.freeBuffer(ptr);
    expect(() => bridge.readBuffer(ptr, 64)).toThrow();
  });

  it('writeBuffer y readBuffer preservan los bytes exactamente', () => {
    const bridge = createWasmBridge();
    const data = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
    const ptr = bridge.allocateBuffer(data.byteLength);
    bridge.writeBuffer(ptr, data);
    const result = bridge.readBuffer(ptr, data.byteLength);
    expect(new Uint8Array(result)).toEqual(data);
    bridge.freeBuffer(ptr);
  });

  it('retorna MEMORY_LIMIT_EXCEEDED al superar 120MB', () => {
    const bridge = createWasmBridge();
    // Alocar casi todo el límite
    const bigSize = MAX_MEMORY_BYTES - 1024;
    const ptr = bridge.allocateBuffer(bigSize);
    // El siguiente alloc debe fallar
    expect(() => bridge.allocateBuffer(2048)).toThrow(MEMORY_LIMIT_EXCEEDED);
    bridge.freeBuffer(ptr);
  });

  it('getMemoryUsageBytes refleja correctamente los bloques activos', () => {
    const bridge = createWasmBridge();
    expect(bridge.getMemoryUsageBytes()).toBe(0);
    const ptr1 = bridge.allocateBuffer(1000);
    expect(bridge.getMemoryUsageBytes()).toBe(1000);
    const ptr2 = bridge.allocateBuffer(500);
    expect(bridge.getMemoryUsageBytes()).toBe(1500);
    bridge.freeBuffer(ptr1);
    expect(bridge.getMemoryUsageBytes()).toBe(500);
    bridge.freeBuffer(ptr2);
    expect(bridge.getMemoryUsageBytes()).toBe(0);
  });

  it('processBytes en modo sin Wasm retorna un pointer válido con los mismos bytes', () => {
    const bridge = createWasmBridge();
    const data = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x05]);
    const ptr = bridge.allocateBuffer(data.byteLength);
    bridge.writeBuffer(ptr, data);
    const resultPtr = bridge.processBytes(ptr, data.byteLength, EVASION_STATE.SPLIT);
    expect(resultPtr).toBeGreaterThan(0);
    const result = bridge.readBuffer(resultPtr, data.byteLength);
    expect(new Uint8Array(result)).toEqual(data);
    bridge.freeBuffer(ptr);
    bridge.freeBuffer(resultPtr);
  });
});
