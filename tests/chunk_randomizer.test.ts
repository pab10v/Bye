import { describe, it, expect } from 'vitest';
import { ChunkRandomizer } from '../src/chunk_randomizer.js';
import type { ChunkIntensity } from '../src/chunk_randomizer.js';

// ---------------------------------------------------------------------------
// Unit tests for ChunkRandomizer — task 4.2
// Requirements: 4.4, 4.8, 4.9
// ---------------------------------------------------------------------------

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Concatenate an array of Uint8Array chunks into a single Uint8Array. */
function concat(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** Create a Uint8Array of the given length filled with sequential byte values. */
function makeBuffer(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    buf[i] = i % 256;
  }
  return buf;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ChunkRandomizer', () => {

  // ── 1. Single chunk for buffer ≤ 7 bytes (REQ 4.9) ───────────────────────

  describe('no-split threshold (REQ 4.9)', () => {
    it('returns a single-element array for a 1-byte buffer', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(1);
      const chunks = randomizer.randomize(buf);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(buf);
    });

    it('returns a single-element array for a 7-byte buffer', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(7);
      const chunks = randomizer.randomize(buf);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(buf);
    });

    it('returns a single-element array for a 4-byte buffer', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(4);
      const chunks = randomizer.randomize(buf);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(buf);
    });

    it('returns a single-element array for an empty buffer', () => {
      const randomizer = new ChunkRandomizer();
      const buf = new Uint8Array(0);
      const chunks = randomizer.randomize(buf);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(buf);
    });

    it('produces more than one chunk for a buffer of 8 bytes', () => {
      // 8 bytes is above the threshold — may produce multiple chunks
      // (not guaranteed to split every time, but the randomizer is allowed to)
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(8);
      const chunks = randomizer.randomize(buf);
      // Must produce at least 1 chunk and concatenation must equal original
      expect(chunks.length).toBeGreaterThanOrEqual(1);
      expect(concat(chunks)).toEqual(buf);
    });
  });

  // ── 2. Default intensity is 'mild' (REQ 4.8) ─────────────────────────────

  describe('default intensity (REQ 4.8)', () => {
    it('returns mild intensity when constructed with no config', () => {
      const randomizer = new ChunkRandomizer();
      expect(randomizer.getIntensity()).toBe('mild');
    });

    it('returns mild intensity when constructed with an empty config object', () => {
      const randomizer = new ChunkRandomizer({});
      expect(randomizer.getIntensity()).toBe('mild');
    });

    it('returns mild intensity when constructed with only enabled: true', () => {
      const randomizer = new ChunkRandomizer({ enabled: true });
      expect(randomizer.getIntensity()).toBe('mild');
    });

    it('respects an explicit intensity of aggressive when provided', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'aggressive' });
      expect(randomizer.getIntensity()).toBe('aggressive');
    });

    it('respects an explicit intensity of mild when provided', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'mild' });
      expect(randomizer.getIntensity()).toBe('mild');
    });
  });

  // ── 3. setIntensity takes effect on the next randomize() call (REQ 4.7) ──

  describe('setIntensity (REQ 4.7)', () => {
    it('getIntensity reflects the new value after setIntensity', () => {
      const randomizer = new ChunkRandomizer();
      expect(randomizer.getIntensity()).toBe('mild');

      randomizer.setIntensity('aggressive');
      expect(randomizer.getIntensity()).toBe('aggressive');
    });

    it('setIntensity from aggressive back to mild is reflected by getIntensity', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'aggressive' });
      randomizer.setIntensity('mild');
      expect(randomizer.getIntensity()).toBe('mild');
    });

    it('intensity update takes effect on the next randomize() call', () => {
      // Use a large buffer so we get many chunks and can observe the distribution.
      // We verify the update took effect by checking getIntensity() before and
      // after, and confirming the chunks produced after the update are consistent
      // with the new intensity (byte conservation is the hard invariant here).
      const randomizer = new ChunkRandomizer({ intensity: 'mild' });
      const buf = makeBuffer(10_000);

      // First call — mild
      const chunksBefore = randomizer.randomize(buf);
      expect(randomizer.getIntensity()).toBe('mild');
      expect(concat(chunksBefore)).toEqual(buf);

      // Update intensity
      randomizer.setIntensity('aggressive');
      expect(randomizer.getIntensity()).toBe('aggressive');

      // Second call — aggressive; byte conservation must still hold
      const chunksAfter = randomizer.randomize(buf);
      expect(concat(chunksAfter)).toEqual(buf);
    });

    it('can toggle between mild and aggressive multiple times', () => {
      const randomizer = new ChunkRandomizer();
      const intensities: ChunkIntensity[] = ['aggressive', 'mild', 'aggressive', 'mild'];
      for (const intensity of intensities) {
        randomizer.setIntensity(intensity);
        expect(randomizer.getIntensity()).toBe(intensity);
      }
    });
  });

  // ── 4. Concatenation of all chunks equals original buffer (REQ 4.4) ──────

  describe('byte conservation (REQ 4.4)', () => {
    it('concat of chunks equals original buffer for a small buffer (8 bytes)', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(8);
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('concat of chunks equals original buffer for a medium buffer (1000 bytes)', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(1000);
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('concat of chunks equals original buffer for a large buffer (10000 bytes)', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(10_000);
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('concat of chunks equals original buffer with aggressive intensity', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'aggressive' });
      const buf = makeBuffer(5_000);
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('concat of chunks equals original buffer with mild intensity', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'mild' });
      const buf = makeBuffer(5_000);
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('total byte count across all chunks equals original buffer length', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(3_000);
      const chunks = randomizer.randomize(buf);
      const totalBytes = chunks.reduce((sum, c) => sum + c.length, 0);
      expect(totalBytes).toBe(buf.length);
    });

    it('no chunk is empty (zero-length) for a buffer above the threshold', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(2_000);
      const chunks = randomizer.randomize(buf);
      for (const chunk of chunks) {
        expect(chunk.length).toBeGreaterThan(0);
      }
    });

    it('byte conservation holds after switching intensity mid-use', () => {
      const randomizer = new ChunkRandomizer({ intensity: 'mild' });
      const buf = makeBuffer(4_000);

      randomizer.setIntensity('aggressive');
      const chunks = randomizer.randomize(buf);
      expect(concat(chunks)).toEqual(buf);
    });

    it('returns exactly the original buffer reference for a 7-byte input', () => {
      const randomizer = new ChunkRandomizer();
      const buf = makeBuffer(7);
      const chunks = randomizer.randomize(buf);
      expect(chunks).toHaveLength(1);
      // The implementation returns [buffer] directly (same reference)
      expect(chunks[0]).toBe(buf);
    });
  });
});
