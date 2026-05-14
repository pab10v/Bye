/**
 * ChunkRandomizer — Non-uniform chunk size randomization for DISORDER state.
 *
 * Varies WritableStream chunk sizes using a non-uniform distribution mixing
 * small (1–7 byte) and normal-sized (256–1460 byte) segments, breaking DPI
 * segment-size fingerprinting. Inspired by Zapret.
 *
 * Requirements: 4.1–4.9, 8.2
 */

import type { ChunkIntensity } from './types.js';

// ---------------------------------------------------------------------------
// Re-export ChunkIntensity from types for consumers of this module
// ---------------------------------------------------------------------------

export type { ChunkIntensity };

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface ChunkRandomizerConfig {
  /** Default: 'mild' (REQ 4.8) */
  intensity: ChunkIntensity;
  /** Default: false (REQ 8.2) */
  enabled: boolean;
}

export interface ChunkRandomizerInterface {
  /** Splits buffer into chunks using the configured non-uniform distribution. */
  randomize(buffer: Uint8Array): Uint8Array[];
  /** Update intensity; takes effect on the next call to randomize(). */
  setIntensity(intensity: ChunkIntensity): void;
  getIntensity(): ChunkIntensity;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Small chunk range: [1, 7] bytes */
const SMALL_MIN = 1;
const SMALL_MAX = 7;

/** Normal chunk range: [256, 1460] bytes (MTU-aware) */
const NORMAL_MIN = 256;
const NORMAL_MAX = 1460;

/**
 * Threshold below which a buffer is returned as a single chunk (REQ 4.9).
 * Buffers of length ≤ 7 bytes are not split.
 */
const NO_SPLIT_THRESHOLD = 7;

// ---------------------------------------------------------------------------
// CSPRNG helpers (REQ 4.6)
// ---------------------------------------------------------------------------

/**
 * Returns a cryptographically random float in [0, 1) using
 * crypto.getRandomValues for unpredictability.
 */
function cryptoRandomFloat(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  // Divide by 0xFFFFFFFF (max uint32) to get a value in [0, 1]
  // We use 0xFFFFFFFF + 1 = 2^32 to get [0, 1) strictly
  return buf[0] / 0x100000000;
}

/**
 * Returns a cryptographically random unsigned 32-bit integer.
 */
function cryptoRandomUint32(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0];
}

// ---------------------------------------------------------------------------
// ChunkRandomizer
// ---------------------------------------------------------------------------

export class ChunkRandomizer implements ChunkRandomizerInterface {
  private intensity: ChunkIntensity;
  private readonly enabled: boolean;

  constructor(config: Partial<ChunkRandomizerConfig> = {}) {
    this.intensity = config.intensity ?? 'mild'; // REQ 4.8: default 'mild'
    this.enabled = config.enabled ?? false;       // REQ 8.2: default disabled
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Splits `buffer` into chunks using the configured non-uniform distribution.
   *
   * - Returns `[buffer]` for buffers ≤ 7 bytes (REQ 4.9).
   * - mild:       P(normal) = 0.5 → ≥ 50% chunks in 256–1460 byte range (REQ 4.2)
   * - aggressive: P(small)  = 0.7 → ≥ 70% chunks in 1–7 byte range (REQ 4.3)
   * - Concatenation of all returned chunks equals the original buffer (REQ 4.4).
   * - Uses crypto.getRandomValues for CSPRNG (REQ 4.6).
   */
  randomize(buffer: Uint8Array): Uint8Array[] {
    // REQ 4.9: no split for tiny buffers
    if (buffer.length <= NO_SPLIT_THRESHOLD) {
      return [buffer];
    }

    const chunks: Uint8Array[] = [];
    let offset = 0;

    while (offset < buffer.length) {
      const remaining = buffer.length - offset;

      // Determine chunk size category based on intensity and CSPRNG
      const r = cryptoRandomFloat(); // uniform [0, 1)

      let useNormal: boolean;
      if (this.intensity === 'mild') {
        // ≥50% normal, ≤50% small → use normal when r < 0.5 (REQ 4.2)
        useNormal = r < 0.5;
      } else {
        // aggressive: ≥70% small, ≤30% normal → use normal when r ≥ 0.7 (REQ 4.3)
        useNormal = r >= 0.7;
      }

      let size: number;
      if (useNormal) {
        // Draw size from normal range [256, 1460], capped at remaining
        size = Math.min(remaining, NORMAL_MIN + (cryptoRandomUint32() % (NORMAL_MAX - NORMAL_MIN + 1)));
      } else {
        // Draw size from small range [1, 7], capped at remaining
        size = Math.min(remaining, SMALL_MIN + (cryptoRandomUint32() % SMALL_MAX));
      }

      chunks.push(buffer.slice(offset, offset + size));
      offset += size;
    }

    return chunks;
  }

  /**
   * Update intensity; takes effect on the next call to randomize() (REQ 4.7).
   */
  setIntensity(intensity: ChunkIntensity): void {
    this.intensity = intensity;
  }

  /** Returns the current intensity setting. */
  getIntensity(): ChunkIntensity {
    return this.intensity;
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _instance: ChunkRandomizer | null = null;

/**
 * Returns the singleton ChunkRandomizer instance.
 * Creates a default instance (mild intensity, disabled) if none exists.
 */
export function getChunkRandomizer(): ChunkRandomizer {
  if (!_instance) {
    _instance = new ChunkRandomizer();
  }
  return _instance;
}

/**
 * Replaces (or clears) the singleton instance.
 * Pass `null` to reset to a fresh default instance on next access.
 * Pass a pre-constructed instance to set a specific configuration.
 * Used by background.ts initialization and by tests.
 */
export function resetChunkRandomizer(instance: ChunkRandomizer | null = null): void {
  _instance = instance;
}
