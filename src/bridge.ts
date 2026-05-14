import { EvasionState, MEMORY_LIMIT_EXCEEDED } from './types.js';

export const MAX_MEMORY_BYTES = 120 * 1024 * 1024; // 120MB

// Public interface of the bridge
export interface WasmNetworkBridge {
  allocateBuffer(size: number): number;
  freeBuffer(pointer: number): void;
  writeBuffer(pointer: number, data: Uint8Array): void;
  readBuffer(pointer: number, length: number): ArrayBuffer;
  processBytes(pointer: number, length: number, state: EvasionState): number;
  getMemoryUsageBytes(): number;
  triggerGC(): void;
}

// Allocated memory block (for leak tracking)
interface MemoryBlock {
  pointer: number;
  size: number;
  freed: boolean;
}

// Declare optional Go-exported globals for Wasm integration
declare const window: {
  ppoBridgeProcessBytes?: (pointer: number, length: number, state: EvasionState) => number;
  ppoBridgeTriggerGC?: () => void;
} & typeof globalThis;

/**
 * WasmBridge implements WasmNetworkBridge using a simulated 128MB linear
 * ArrayBuffer. In production, this delegates to Go-Wasm exported functions
 * when available (window.ppoBridgeProcessBytes / window.ppoBridgeTriggerGC).
 */
class WasmBridge implements WasmNetworkBridge {
  // 128MB simulated linear memory (matches Wasm linear memory model)
  private readonly memory: ArrayBuffer = new ArrayBuffer(128 * 1024 * 1024);
  private readonly blocks: Map<number, MemoryBlock> = new Map();
  // Bump pointer allocator — starts at offset 1 so pointer 0 is never valid
  private bumpOffset: number = 1;

  allocateBuffer(size: number): number {
    if (size <= 0) {
      throw new Error(MEMORY_LIMIT_EXCEEDED);
    }
    if (this.getMemoryUsageBytes() + size > MAX_MEMORY_BYTES) {
      throw new Error(MEMORY_LIMIT_EXCEEDED);
    }

    const pointer = this.bumpOffset;
    this.bumpOffset += size;

    const block: MemoryBlock = { pointer, size, freed: false };
    this.blocks.set(pointer, block);

    return pointer;
  }

  freeBuffer(pointer: number): void {
    const block = this.blocks.get(pointer);
    if (!block) {
      // Unknown pointer — no-op, no error
      return;
    }
    block.freed = true;
  }

  writeBuffer(pointer: number, data: Uint8Array): void {
    const block = this.blocks.get(pointer);
    if (!block) {
      throw new Error(`writeBuffer: unknown pointer ${pointer}`);
    }
    if (block.freed) {
      throw new Error(`writeBuffer: pointer ${pointer} has been freed`);
    }

    const view = new Uint8Array(this.memory, pointer, data.byteLength);
    view.set(data);
  }

  readBuffer(pointer: number, length: number): ArrayBuffer {
    const block = this.blocks.get(pointer);
    if (!block) {
      throw new Error(`readBuffer: unknown pointer ${pointer}`);
    }
    if (block.freed) {
      throw new Error(`readBuffer: pointer ${pointer} has been freed`);
    }

    // Return a copy of the bytes (ArrayBuffer slice)
    return this.memory.slice(pointer, pointer + length);
  }

  processBytes(pointer: number, length: number, state: EvasionState): number {
    // Delegate to Go-Wasm function if available (production path)
    if (
      typeof globalThis !== 'undefined' &&
      (globalThis as typeof window).ppoBridgeProcessBytes
    ) {
      return (globalThis as typeof window).ppoBridgeProcessBytes!(pointer, length, state);
    }

    // Test / no-Wasm mode: identity transform — copy bytes to a new buffer
    const block = this.blocks.get(pointer);
    if (!block || block.freed) {
      throw new Error(`processBytes: invalid or freed pointer ${pointer}`);
    }

    const sourceView = new Uint8Array(this.memory, pointer, length);
    const resultPtr = this.allocateBuffer(length);
    const destView = new Uint8Array(this.memory, resultPtr, length);
    destView.set(sourceView);

    return resultPtr;
  }

  getMemoryUsageBytes(): number {
    let total = 0;
    for (const block of this.blocks.values()) {
      if (!block.freed) {
        total += block.size;
      }
    }
    return total;
  }

  triggerGC(): void {
    if (
      typeof globalThis !== 'undefined' &&
      (globalThis as typeof window).ppoBridgeTriggerGC
    ) {
      (globalThis as typeof window).ppoBridgeTriggerGC!();
    }
    // No-op when Wasm is not loaded
  }
}

/**
 * Factory function — creates a fresh WasmNetworkBridge instance.
 * Each call returns an independent bridge with its own memory space.
 */
export function createWasmBridge(): WasmNetworkBridge {
  return new WasmBridge();
}
