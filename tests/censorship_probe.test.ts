import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  type MockInstance,
} from 'vitest';
import { CensorshipProbe } from '../src/censorship_probe.js';
import type { DpiDetector } from '../src/dpi_detector.js';
import type { BypassManager } from '../src/bypass_manager.js';
import type { ProbeResult } from '../src/types.js';

// ---------------------------------------------------------------------------
// Unit tests for CensorshipProbe — task 2.2
// Requirements: 1.1, 1.5, 1.6, 1.8
// ---------------------------------------------------------------------------

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Create a minimal DpiDetector mock. */
function makeDpiDetector(): DpiDetector & {
  recordActiveProbe: MockInstance;
  resetProbeCounters: MockInstance;
} {
  return {
    recordActiveProbe: vi.fn(),
    resetProbeCounters: vi.fn(),
    recordRequest: vi.fn(),
    updateMeshScore: vi.fn(),
    getScore: vi.fn(() => 0),
    getLevel: vi.fn(() => 'none' as const),
    getSnapshot: vi.fn(),
    decay: vi.fn(),
  } as unknown as DpiDetector & {
    recordActiveProbe: MockInstance;
    resetProbeCounters: MockInstance;
  };
}

/** Create a minimal BypassManager mock. */
function makeBypassManager(): BypassManager & {
  addRule: MockInstance;
  removeRule: MockInstance;
} {
  return {
    addRule: vi.fn(),
    removeRule: vi.fn(),
    shouldBypass: vi.fn(() => false),
    getRuleCount: vi.fn(() => 0),
  } as unknown as BypassManager & {
    addRule: MockInstance;
    removeRule: MockInstance;
  };
}

/**
 * Build a mock fetch that resolves immediately (no setTimeout) with the given
 * HTTP status. Using no setTimeout avoids triggering the fake-timer infinite
 * loop guard when vi.runAllTimersAsync() is called.
 */
function makeFetchSuccess(status = 200): typeof fetch {
  return vi.fn((_url: RequestInfo | URL, _init?: RequestInit) =>
    Promise.resolve({ status, ok: status >= 200 && status < 300 } as Response),
  ) as unknown as typeof fetch;
}

/**
 * Build a mock fetch that rejects with an AbortError when the AbortSignal fires.
 * The promise never resolves on its own — it only rejects when aborted.
 */
function makeFetchAbort(): typeof fetch {
  return vi.fn((_url: RequestInfo | URL, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      const signal = (init as RequestInit & { signal?: AbortSignal })?.signal;
      if (signal) {
        if (signal.aborted) {
          reject(new DOMException('The operation was aborted.', 'AbortError'));
          return;
        }
        signal.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        });
      }
    }),
  ) as unknown as typeof fetch;
}

/**
 * Build a mock fetch that rejects immediately with a TypeError (network error).
 */
function makeFetchNetworkError(): typeof fetch {
  return vi.fn(() =>
    Promise.reject(new TypeError('Failed to fetch')),
  ) as unknown as typeof fetch;
}

/**
 * Run one probe cycle by:
 * 1. Starting the probe (schedules a timer).
 * 2. Advancing fake timers past the interval.
 * 3. Flushing all pending microtasks/promises.
 * 4. Stopping the probe to prevent rescheduling.
 */
async function runOneCycle(
  probe: CensorshipProbe,
  intervalMs: number,
): Promise<void> {
  probe.start();
  // Advance past the interval to fire the scheduled setTimeout.
  await vi.advanceTimersByTimeAsync(intervalMs + 1);
  // Stop before the rescheduled timer fires again.
  probe.stop();
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('CensorshipProbe', () => {
  let dpi: ReturnType<typeof makeDpiDetector>;
  let bm: ReturnType<typeof makeBypassManager>;

  beforeEach(() => {
    dpi = makeDpiDetector();
    bm = makeBypassManager();
    vi.useFakeTimers();
    vi.stubGlobal('fetch', makeFetchSuccess(200));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  // ── 1. Default canary list (REQ 1.1) ──────────────────────────────────────

  describe('default canary list', () => {
    it('has at least 5 entries when constructed with no config', async () => {
      const probe = new CensorshipProbe(dpi, bm);
      await runOneCycle(probe, 300_000);

      const results = probe.getLatestResults();
      expect(results.size).toBeGreaterThanOrEqual(5);
    });

    it('default canary URLs include the five well-known blocked domains', async () => {
      const fetchMock = makeFetchSuccess(200);
      vi.stubGlobal('fetch', fetchMock);

      const probe = new CensorshipProbe(dpi, bm);
      await runOneCycle(probe, 300_000);

      const calledUrls = (fetchMock as MockInstance).mock.calls.map(
        (c: unknown[]) => c[0] as string,
      );
      expect(calledUrls.some((u) => u.includes('bbc.com'))).toBe(true);
      expect(calledUrls.some((u) => u.includes('twitter.com'))).toBe(true);
      expect(calledUrls.some((u) => u.includes('youtube.com'))).toBe(true);
      expect(calledUrls.some((u) => u.includes('facebook.com'))).toBe(true);
      expect(calledUrls.some((u) => u.includes('wikipedia.org'))).toBe(true);
    });
  });

  // ── 2. Fetch timeout → connectionFailed = true, ttfbMs = fetchTimeoutMs ──

  describe('fetch timeout handling (REQ 1.10)', () => {
    it('records connectionFailed = true when fetch times out (AbortError)', async () => {
      vi.stubGlobal('fetch', makeFetchAbort());

      const fetchTimeoutMs = 10_000;
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://example.com'],
        fetchTimeoutMs,
        probeIntervalMs: 1_000,
        enabled: false,
      });

      probe.start();
      // Advance past the probe interval to start the cycle.
      await vi.advanceTimersByTimeAsync(1_001);
      // Advance past the fetch timeout so AbortController fires.
      await vi.advanceTimersByTimeAsync(fetchTimeoutMs + 1);
      probe.stop();

      const result = probe.getLatestResults().get('https://example.com');
      expect(result).toBeDefined();
      expect(result!.connectionFailed).toBe(true);
    });

    it('records ttfbMs equal to fetchTimeoutMs on AbortError', async () => {
      vi.stubGlobal('fetch', makeFetchAbort());

      const fetchTimeoutMs = 10_000;
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://example.com'],
        fetchTimeoutMs,
        probeIntervalMs: 1_000,
        enabled: false,
      });

      probe.start();
      await vi.advanceTimersByTimeAsync(1_001);
      await vi.advanceTimersByTimeAsync(fetchTimeoutMs + 1);
      probe.stop();

      const result = probe.getLatestResults().get('https://example.com');
      expect(result).toBeDefined();
      expect(result!.ttfbMs).toBe(fetchTimeoutMs);
    });

    it('records connectionFailed = true on network TypeError', async () => {
      vi.stubGlobal('fetch', makeFetchNetworkError());

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://example.com'],
        fetchTimeoutMs: 10_000,
        probeIntervalMs: 1_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const result = probe.getLatestResults().get('https://example.com');
      expect(result).toBeDefined();
      expect(result!.connectionFailed).toBe(true);
    });

    it('records connectionFailed = false and httpStatus on successful fetch', async () => {
      vi.stubGlobal('fetch', makeFetchSuccess(200));

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://example.com'],
        fetchTimeoutMs: 10_000,
        probeIntervalMs: 1_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const result = probe.getLatestResults().get('https://example.com');
      expect(result).toBeDefined();
      expect(result!.connectionFailed).toBe(false);
      expect(result!.httpStatus).toBe(200);
    });
  });

  // ── 3. recordActiveProbe called once per URL per cycle (REQ 1.4) ──────────

  describe('recordActiveProbe call count (REQ 1.4)', () => {
    it('calls recordActiveProbe exactly once per URL in a single cycle', async () => {
      const canaryUrls = [
        'https://a.example.com',
        'https://b.example.com',
        'https://c.example.com',
      ];

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      expect(dpi.recordActiveProbe).toHaveBeenCalledTimes(canaryUrls.length);
    });

    it('passes the correct URL in the ProbeResult to recordActiveProbe', async () => {
      const canaryUrls = ['https://x.example.com', 'https://y.example.com'];

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const calledWith = (dpi.recordActiveProbe as MockInstance).mock.calls.map(
        (c: unknown[]) => (c[0] as ProbeResult).url,
      );
      expect(calledWith).toContain('https://x.example.com');
      expect(calledWith).toContain('https://y.example.com');
    });

    it('calls resetProbeCounters once at the start of each cycle', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      // First cycle
      await runOneCycle(probe, 1_000);
      expect(dpi.resetProbeCounters).toHaveBeenCalledTimes(1);

      // Second cycle
      await runOneCycle(probe, 1_000);
      expect(dpi.resetProbeCounters).toHaveBeenCalledTimes(2);
    });
  });

  // ── 4. Bypass rules added before cycle and removed after (REQ 1.8) ────────

  describe('bypass rule lifecycle (REQ 1.8)', () => {
    it('adds each canary URL to bypass manager before fetching', async () => {
      const canaryUrls = ['https://a.example.com', 'https://b.example.com'];

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      for (const url of canaryUrls) {
        expect(bm.addRule).toHaveBeenCalledWith(url);
      }
    });

    it('removes each canary URL from bypass manager after the cycle', async () => {
      const canaryUrls = ['https://a.example.com', 'https://b.example.com'];

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      for (const url of canaryUrls) {
        expect(bm.removeRule).toHaveBeenCalledWith(url);
      }
    });

    it('removes bypass rules even when a fetch throws (finally block)', async () => {
      const canaryUrls = ['https://a.example.com', 'https://b.example.com'];
      let callCount = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          callCount++;
          if (callCount === 2) {
            return Promise.reject(new TypeError('Network error'));
          }
          return Promise.resolve({ status: 200, ok: true } as Response);
        }),
      );

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      // Both URLs must have been removed regardless of the error.
      for (const url of canaryUrls) {
        expect(bm.removeRule).toHaveBeenCalledWith(url);
      }
    });

    it('addRule is called before any fetch call in the cycle', async () => {
      const canaryUrls = ['https://a.example.com'];
      const callOrder: string[] = [];

      bm.addRule.mockImplementation(() => {
        callOrder.push('addRule');
      });

      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          callOrder.push('fetch');
          return Promise.resolve({ status: 200, ok: true } as Response);
        }),
      );

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const addRuleIdx = callOrder.indexOf('addRule');
      const fetchIdx = callOrder.indexOf('fetch');
      expect(addRuleIdx).toBeGreaterThanOrEqual(0);
      expect(fetchIdx).toBeGreaterThan(addRuleIdx);
    });

    it('removeRule is called after all fetch calls complete', async () => {
      const canaryUrls = ['https://a.example.com'];
      const callOrder: string[] = [];

      bm.removeRule.mockImplementation(() => {
        callOrder.push('removeRule');
      });

      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          callOrder.push('fetch');
          return Promise.resolve({ status: 200, ok: true } as Response);
        }),
      );

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls,
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const fetchIdx = callOrder.indexOf('fetch');
      const removeRuleIdx = callOrder.indexOf('removeRule');
      expect(fetchIdx).toBeGreaterThanOrEqual(0);
      expect(removeRuleIdx).toBeGreaterThan(fetchIdx);
    });
  });

  // ── 5. setProbeInterval cancels current timer and reschedules (REQ 1.6) ───

  describe('setProbeInterval (REQ 1.6)', () => {
    it('does not fire the old interval after setProbeInterval is called', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 5_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      probe.start();

      // Advance 3 000 ms — old timer has not fired yet.
      await vi.advanceTimersByTimeAsync(3_000);
      expect(dpi.recordActiveProbe).not.toHaveBeenCalled();

      // Change interval to 10 000 ms — this cancels the 5 000 ms timer.
      probe.setProbeInterval(10_000);

      // Advance to where the old 5 000 ms timer would have fired (2 001 ms more).
      await vi.advanceTimersByTimeAsync(2_001);
      // No cycle should have fired yet (new timer is 10 000 ms from the reset).
      expect(dpi.recordActiveProbe).not.toHaveBeenCalled();

      probe.stop();
    });

    it('fires the cycle at the new interval after setProbeInterval', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 60_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      probe.start();

      // Switch to a much shorter interval.
      probe.setProbeInterval(2_000);

      // Advance past the new interval.
      await vi.advanceTimersByTimeAsync(2_001);
      probe.stop();

      expect(dpi.recordActiveProbe).toHaveBeenCalled();
    });

    it('setProbeInterval has no effect when probe is stopped', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      // Never start — just call setProbeInterval.
      probe.setProbeInterval(500);

      // Advance well past both intervals.
      await vi.advanceTimersByTimeAsync(5_000);

      // No cycle should have fired.
      expect(dpi.recordActiveProbe).not.toHaveBeenCalled();
    });

    it('updates the stored interval so subsequent cycles use the new value', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 5_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      probe.start();
      probe.setProbeInterval(1_000);

      // First cycle at new interval.
      await vi.advanceTimersByTimeAsync(1_001);
      expect(dpi.recordActiveProbe).toHaveBeenCalledTimes(1);

      // Second cycle — should also fire at 1 000 ms.
      await vi.advanceTimersByTimeAsync(1_001);
      probe.stop();
      expect(dpi.recordActiveProbe).toHaveBeenCalledTimes(2);
    });
  });

  // ── 6. Additional lifecycle / accessor tests ──────────────────────────────

  describe('lifecycle and accessors', () => {
    it('getLastCycleTimestamp returns null before any cycle runs', () => {
      const probe = new CensorshipProbe(dpi, bm);
      expect(probe.getLastCycleTimestamp()).toBeNull();
    });

    it('getLastCycleTimestamp is set after a cycle completes', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      expect(probe.getLastCycleTimestamp()).not.toBeNull();
    });

    it('getLastCycleFailureCount reflects failed probes', async () => {
      vi.stubGlobal('fetch', makeFetchNetworkError());

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com', 'https://b.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      expect(probe.getLastCycleFailureCount()).toBe(2);
    });

    it('getLastCycleFailureCount is 0 when all probes succeed', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com', 'https://b.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      expect(probe.getLastCycleFailureCount()).toBe(0);
    });

    it('stop() prevents further cycles from firing', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      probe.start();
      probe.stop();

      await vi.advanceTimersByTimeAsync(5_000);

      expect(dpi.recordActiveProbe).not.toHaveBeenCalled();
    });

    it('setCanaryUrls updates the URL list used in subsequent cycles', async () => {
      const fetchMock = makeFetchSuccess(200);
      vi.stubGlobal('fetch', fetchMock);

      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://old.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      probe.setCanaryUrls(['https://new1.example.com', 'https://new2.example.com']);
      await runOneCycle(probe, 1_000);

      const calledUrls = (fetchMock as MockInstance).mock.calls.map(
        (c: unknown[]) => c[0] as string,
      );
      expect(calledUrls).not.toContain('https://old.example.com');
      expect(calledUrls).toContain('https://new1.example.com');
      expect(calledUrls).toContain('https://new2.example.com');
    });

    it('getLatestResults returns a copy (mutation does not affect internal state)', async () => {
      const probe = new CensorshipProbe(dpi, bm, {
        canaryUrls: ['https://a.example.com'],
        probeIntervalMs: 1_000,
        fetchTimeoutMs: 10_000,
        enabled: false,
      });

      await runOneCycle(probe, 1_000);

      const copy1 = probe.getLatestResults();
      copy1.clear();
      const copy2 = probe.getLatestResults();
      expect(copy2.size).toBeGreaterThan(0);
    });
  });
});
