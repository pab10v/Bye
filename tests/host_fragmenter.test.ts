import { describe, it, expect, vi } from 'vitest';

// ---------------------------------------------------------------------------
// Mock the chrome global BEFORE background.ts is imported.
// background.ts calls chrome.runtime.onMessage.addListener at module level,
// so the global must exist when the module is first evaluated.
// vi.hoisted() runs before any imports are processed.
// ---------------------------------------------------------------------------
vi.hoisted(() => {
  (globalThis as any).chrome = {
    runtime: {
      onMessage: { addListener: () => {} },
      lastError: null,
      getURL: (path: string) => path,
    },
    proxy: {
      settings: { set: () => {} },
    },
    alarms: {
      create: () => {},
      onAlarm: { addListener: () => {} },
    },
    storage: {
      session: {
        get: () => Promise.resolve({}),
        set: () => Promise.resolve(),
      },
    },
  };
});

import { fragmentHttpHost } from '../src/background.js';

// ---------------------------------------------------------------------------
// Unit tests for fragmentHttpHost — task 3.2
// Requirements: 3.1, 3.4, 3.5, 3.7, 3.8
// ---------------------------------------------------------------------------

// ── Helpers ──────────────────────────────────────────────────────────────────

const enc = new TextEncoder();

/** Build a minimal HTTP/1.1 request buffer with the given method and host. */
function makeHttpRequest(method: string, host: string): Uint8Array {
  const raw = `${method} / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;
  return enc.encode(raw);
}

/** Concatenate two Uint8Arrays into one. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ── 1. TLS ClientHello passthrough (REQ 8.4) ─────────────────────────────────

describe('fragmentHttpHost — TLS ClientHello passthrough', () => {
  it('returns [buffer] unchanged when buffer[0] === 0x16', () => {
    const buf = new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x28, 0x01]);
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf); // same reference — not a copy
  });

  it('returns exactly one chunk for a TLS ClientHello', () => {
    const buf = new Uint8Array(64);
    buf[0] = 0x16;
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
  });
});

// ── 2. Passthrough for buffer with no Host: header (REQ 3.4) ─────────────────

describe('fragmentHttpHost — no Host header passthrough', () => {
  it('returns [buffer] when a valid HTTP method is present but no Host: header', () => {
    const buf = enc.encode('GET / HTTP/1.1\r\nConnection: close\r\n\r\n');
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });

  it('returns [buffer] for a POST request with no Host: header', () => {
    const buf = enc.encode('POST /submit HTTP/1.1\r\nContent-Length: 0\r\n\r\n');
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });
});

// ── 3. Passthrough for non-HTTP buffers (REQ 3.7) ────────────────────────────

describe('fragmentHttpHost — non-HTTP buffer passthrough', () => {
  it('returns [buffer] for a buffer that does not start with any HTTP method token', () => {
    const buf = enc.encode('HELLO world\r\n');
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });

  it('returns [buffer] for an empty buffer', () => {
    const buf = new Uint8Array(0);
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });

  it('returns [buffer] for arbitrary binary data', () => {
    const buf = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });
});

// ── 4. Passthrough for 1-byte host value (REQ 3.5) ───────────────────────────

describe('fragmentHttpHost — 1-byte host value passthrough', () => {
  it('returns [buffer] when the Host: header value is exactly 1 byte', () => {
    const buf = enc.encode('GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n');
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });

  it('returns [buffer] when the Host: header value is empty (0 bytes)', () => {
    const buf = enc.encode('GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n');
    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(buf);
  });
});

// ── 5. Correct split for all 8 HTTP method tokens (REQ 3.1, 3.7) ─────────────

describe('fragmentHttpHost — correct split for all 8 HTTP method tokens', () => {
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];

  for (const method of methods) {
    it(`splits the buffer for a ${method} request with a valid Host: header`, () => {
      const host = 'example.com';
      const buf = makeHttpRequest(method, host);
      const result = fragmentHttpHost(buf);

      // Must produce exactly 2 chunks
      expect(result).toHaveLength(2);

      // Both chunks must be non-empty
      expect(result[0].length).toBeGreaterThan(0);
      expect(result[1].length).toBeGreaterThan(0);
    });
  }
});

// ── 6. Concatenation of returned chunks equals original buffer (REQ 3.8) ─────

describe('fragmentHttpHost — byte conservation (REQ 3.8)', () => {
  it('chunk1 ++ chunk2 equals the original buffer for a GET request', () => {
    const buf = makeHttpRequest('GET', 'example.com');
    const result = fragmentHttpHost(buf);

    expect(result).toHaveLength(2);
    const rejoined = concat(result[0], result[1]);
    expect(rejoined).toEqual(buf);
  });

  it('total byte count is preserved: len(chunk1) + len(chunk2) === len(buffer)', () => {
    const buf = makeHttpRequest('POST', 'www.example.org');
    const result = fragmentHttpHost(buf);

    expect(result).toHaveLength(2);
    expect(result[0].length + result[1].length).toBe(buf.length);
  });

  it('split point falls within the Host: header value (k ∈ [1, hostValueLen-1])', () => {
    const host = 'example.com'; // 11 bytes
    const buf = makeHttpRequest('GET', host);
    const text = new TextDecoder('ascii').decode(buf);

    // Locate the value start in the original buffer
    const lowerText = text.toLowerCase();
    const hostHeaderIdx = lowerText.indexOf('host:');
    let valueStart = hostHeaderIdx + 5;
    while (valueStart < text.length && text[valueStart] === ' ') valueStart++;

    const result = fragmentHttpHost(buf);
    expect(result).toHaveLength(2);

    // chunk1 must end somewhere inside the host value
    const splitPoint = result[0].length;
    expect(splitPoint).toBeGreaterThanOrEqual(valueStart + 1);
    expect(splitPoint).toBeLessThanOrEqual(valueStart + host.length - 1);
  });

  it('byte conservation holds for a request with a long host value', () => {
    const host = 'very-long-subdomain.example.co.uk';
    const buf = makeHttpRequest('DELETE', host);
    const result = fragmentHttpHost(buf);

    expect(result).toHaveLength(2);
    const rejoined = concat(result[0], result[1]);
    expect(rejoined).toEqual(buf);
  });

  it('byte conservation holds for a request using LF-only line endings', () => {
    const raw = 'GET / HTTP/1.1\nHost: example.com\nConnection: close\n\n';
    const buf = enc.encode(raw);
    const result = fragmentHttpHost(buf);

    // Should split (host value is 11 bytes ≥ 2)
    expect(result).toHaveLength(2);
    const rejoined = concat(result[0], result[1]);
    expect(rejoined).toEqual(buf);
  });

  it('byte conservation holds for a case-insensitive Host: header (HOST:)', () => {
    const raw = 'GET / HTTP/1.1\r\nHOST: example.com\r\nConnection: close\r\n\r\n';
    const buf = enc.encode(raw);
    const result = fragmentHttpHost(buf);

    expect(result).toHaveLength(2);
    const rejoined = concat(result[0], result[1]);
    expect(rejoined).toEqual(buf);
  });

  it('byte conservation holds for a 2-byte host value (minimum splittable)', () => {
    const buf = enc.encode('GET / HTTP/1.1\r\nHost: ab\r\nConnection: close\r\n\r\n');
    const result = fragmentHttpHost(buf);

    // 2-byte host value → exactly one valid split point (k=1)
    expect(result).toHaveLength(2);
    const rejoined = concat(result[0], result[1]);
    expect(rejoined).toEqual(buf);
  });
});

// ── 7. Split point is within valid range across multiple calls (REQ 3.2) ──────

describe('fragmentHttpHost — stochastic split offset range', () => {
  it('split point always falls within [valueStart+1, valueStart+hostValueLen-1] over many calls', () => {
    const host = 'example.com'; // 11 bytes → k ∈ [1, 10]
    const buf = makeHttpRequest('GET', host);
    const text = new TextDecoder('ascii').decode(buf);
    const lowerText = text.toLowerCase();
    const hostHeaderIdx = lowerText.indexOf('host:');
    let valueStart = hostHeaderIdx + 5;
    while (valueStart < text.length && text[valueStart] === ' ') valueStart++;
    const hostValueLen = host.length;

    const splitPoints = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const result = fragmentHttpHost(buf);
      expect(result).toHaveLength(2);
      const sp = result[0].length;
      expect(sp).toBeGreaterThanOrEqual(valueStart + 1);
      expect(sp).toBeLessThanOrEqual(valueStart + hostValueLen - 1);
      splitPoints.add(sp);
    }

    // With 200 iterations and 10 possible split points, we expect > 1 unique split
    expect(splitPoints.size).toBeGreaterThan(1);
  });
});
