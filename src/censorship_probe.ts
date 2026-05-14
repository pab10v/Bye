/**
 * CensorshipProbe — Active canary measurement component
 *
 * Periodically fetches known-blocked domains and feeds TLS anomaly signals
 * into the existing DpiDetector. Inspired by OONI Probe.
 *
 * Requirements: 1.1–1.11, 2.7
 */

import type { ProbeResult, CensorshipProbeConfig, CanaryUrlEntry } from './types.js';
import type { DpiDetector } from './dpi_detector.js';
import type { BypassManager } from './bypass_manager.js';

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface CensorshipProbeInterface {
  /** Start the repeating probe cycle. */
  start(): void;
  /** Stop the probe cycle and cancel any pending timer. */
  stop(): void;
  /** Returns the most recent ProbeResult for each canary URL. */
  getLatestResults(): Map<string, ProbeResult>;
  /** Returns the timestamp of the last completed cycle (null if never run). */
  getLastCycleTimestamp(): number | null;
  /** Returns the count of failed probes in the last cycle. */
  getLastCycleFailureCount(): number;
  /** Update the probe interval; cancels current timer and reschedules immediately. */
  setProbeInterval(ms: number): void;
  /** Update the canary URL list. */
  setCanaryUrls(urls: string[]): void;
  /** Returns the effective URL list with status for each entry (for UI display). */
  getCanaryEntries(): CanaryUrlEntry[];
  /**
   * Sets user-defined canary URLs. Each URL is validated:
   * - Must be parseable as a URL
   * - Must use https:// scheme
   * - Invalid URLs are rejected (not added), valid ones replace the user list
   * Returns an array of validation errors (empty = all valid).
   */
  setUserCanaryUrls(urls: string[]): string[];
  /** Returns the current user-defined URLs (raw strings, may include invalid ones for UI editing). */
  getUserCanaryUrls(): string[];
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

/** Five domains known to be blocked in censorship regimes (REQ 1.1) */
const DEFAULT_CANARY_URLS: string[] = [
  'https://www.bbc.com',
  'https://twitter.com',
  'https://www.youtube.com',
  'https://www.facebook.com',
  'https://www.wikipedia.org',
];

const DEFAULT_PROBE_INTERVAL_MS = 300_000; // 5 minutes (REQ 1.5)
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;   // 10 seconds (REQ 1.2)

/** Number of consecutive failures before a user URL is permanently replaced by its hardwired fallback */
const PERMANENT_FAILURE_THRESHOLD = 3;

// ---------------------------------------------------------------------------
// CensorshipProbe
// ---------------------------------------------------------------------------

export class CensorshipProbe implements CensorshipProbeInterface {
  private canaryUrls: string[];
  private probeIntervalMs: number;
  private readonly fetchTimeoutMs: number;
  private enabled: boolean;

  private latestResults: Map<string, ProbeResult> = new Map();
  private lastCycleAt: number | null = null;
  private lastCycleFailureCount: number = 0;

  private timerId: ReturnType<typeof setTimeout> | null = null;

  private readonly dpiDetector: DpiDetector;
  private readonly bypassManager: BypassManager;

  /** Raw user-supplied URLs (may include invalid ones for UI editing) */
  private userCanaryUrls: string[] = [];

  /** Consecutive failure counts per URL */
  private consecutiveFailures: Map<string, number> = new Map();

  constructor(
    dpiDetector: DpiDetector,
    bypassManager: BypassManager,
    config: Partial<CensorshipProbeConfig> = {},
  ) {
    this.dpiDetector = dpiDetector;
    this.bypassManager = bypassManager;

    this.canaryUrls = config.canaryUrls ?? [...DEFAULT_CANARY_URLS];
    this.probeIntervalMs = config.probeIntervalMs ?? DEFAULT_PROBE_INTERVAL_MS;
    this.fetchTimeoutMs = config.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.enabled = config.enabled ?? false; // REQ 8.2: default disabled

    // Restore user canary URLs from config if provided
    if (config.userCanaryUrls && config.userCanaryUrls.length > 0) {
      this.userCanaryUrls = [...config.userCanaryUrls];
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Start the repeating probe cycle (REQ 1.5). */
  start(): void {
    this.enabled = true;
    this._scheduleCycle();
  }

  /** Stop the probe cycle and cancel any pending timer (REQ 1.6). */
  stop(): void {
    this.enabled = false;
    this._cancelTimer();
  }

  /** Returns the most recent ProbeResult for each canary URL (REQ 1.11). */
  getLatestResults(): Map<string, ProbeResult> {
    return new Map(this.latestResults);
  }

  /** Returns the timestamp of the last completed cycle (null if never run). */
  getLastCycleTimestamp(): number | null {
    return this.lastCycleAt;
  }

  /** Returns the count of failed probes in the last cycle. */
  getLastCycleFailureCount(): number {
    return this.lastCycleFailureCount;
  }

  /**
   * Update the probe interval; cancels current timer and reschedules
   * immediately with the new interval (REQ 1.6).
   */
  setProbeInterval(ms: number): void {
    this.probeIntervalMs = ms;
    if (this.enabled) {
      this._cancelTimer();
      this._scheduleCycle();
    }
  }

  /**
   * Update the canary URL list (backward compatibility).
   * Sets the base canary URL list directly. For user-managed URLs with
   * fallback behavior, use setUserCanaryUrls() instead.
   */
  setCanaryUrls(urls: string[]): void {
    this.canaryUrls = [...urls];
  }

  /**
   * Returns the effective URL list with status for each entry (for UI display).
   */
  getCanaryEntries(): CanaryUrlEntry[] {
    const effectiveUrls = this._computeEffectiveUrls();

    return effectiveUrls.map((effectiveUrl, i) => {
      const userUrl = this.userCanaryUrls[i];
      const isUserDefined = userUrl !== undefined;

      if (!isUserDefined) {
        // Hardwired default entry
        const failures = this.consecutiveFailures.get(effectiveUrl) ?? 0;
        return {
          url: effectiveUrl,
          isUserDefined: false,
          status: 'active' as const,
          consecutiveFailures: failures,
        };
      }

      // User-defined slot
      const isValid = this._isValidCanaryUrl(userUrl);
      if (!isValid) {
        return {
          url: effectiveUrl, // shows the hardwired fallback URL
          isUserDefined: true,
          status: 'invalid' as const,
          consecutiveFailures: 0,
        };
      }

      const failures = this.consecutiveFailures.get(userUrl) ?? 0;
      const usingFallback = failures >= PERMANENT_FAILURE_THRESHOLD;

      return {
        url: effectiveUrl,
        isUserDefined: true,
        status: usingFallback ? 'fallback' as const : 'active' as const,
        consecutiveFailures: failures,
      };
    });
  }

  /**
   * Sets user-defined canary URLs. Validates each URL:
   * - Must be parseable as a URL
   * - Must use https:// scheme
   * Invalid URLs are rejected. Returns an array of validation errors.
   */
  setUserCanaryUrls(urls: string[]): string[] {
    const errors: string[] = [];

    for (const url of urls) {
      if (!this._isValidCanaryUrl(url)) {
        errors.push(`Invalid URL: "${url}" — must be a valid https:// URL`);
      }
    }

    if (errors.length === 0) {
      this.userCanaryUrls = [...urls];
    }

    return errors;
  }

  /** Returns the current user-defined URLs (raw strings). */
  getUserCanaryUrls(): string[] {
    return [...this.userCanaryUrls];
  }

  // ── Private ────────────────────────────────────────────────────────────────

  /**
   * Validates a URL for use as a canary URL.
   * Must be parseable, use https:// scheme, and have a non-empty hostname.
   */
  private _isValidCanaryUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:' && parsed.hostname.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Computes the effective URL list for the current probe cycle.
   * - If no user URLs have been set: returns the configured canaryUrls (or hardwired defaults)
   * - For each user URL slot: use user URL if valid and not permanently failed,
   *   otherwise fall back to the corresponding hardwired default
   */
  private _computeEffectiveUrls(): string[] {
    if (this.userCanaryUrls.length === 0) {
      // No user overrides — use the configured canary URLs (may be hardwired defaults)
      return [...this.canaryUrls];
    }

    return this.userCanaryUrls.map((userUrl, i) => {
      const hardwiredFallback = DEFAULT_CANARY_URLS[i % DEFAULT_CANARY_URLS.length];

      if (!this._isValidCanaryUrl(userUrl)) {
        return hardwiredFallback;
      }

      const failures = this.consecutiveFailures.get(userUrl) ?? 0;
      if (failures >= PERMANENT_FAILURE_THRESHOLD) {
        return hardwiredFallback;
      }

      return userUrl;
    });
  }

  private _scheduleCycle(): void {
    this._cancelTimer();
    this.timerId = setTimeout(() => {
      this._runProbeCycle().catch(() => {
        // Swallow errors — probe failures are recorded per-URL
      }).finally(() => {
        if (this.enabled) {
          this._scheduleCycle();
        }
      });
    }, this.probeIntervalMs);
  }

  private _cancelTimer(): void {
    if (this.timerId !== null) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
  }

  /**
   * Run one full probe cycle:
   * 1. Reset DpiDetector probe counters (REQ 2.7)
   * 2. Compute effective URLs (user URLs with fallback to hardwired)
   * 3. Add all effective URLs to bypass manager (REQ 1.8)
   * 4. Fetch each URL, record result, call recordActiveProbe (REQ 1.2–1.4)
   * 5. Update consecutive failure counts
   * 6. Remove bypass rules in finally (REQ 1.8)
   * 7. Update cycle metadata
   */
  private async _runProbeCycle(): Promise<void> {
    // Step 1: reset probe counters at the start of each cycle (REQ 2.7)
    this.dpiDetector.resetProbeCounters();

    // Step 2: compute effective URLs for this cycle
    const effectiveUrls = this._computeEffectiveUrls();

    // Keep canaryUrls in sync only when user URLs are active
    if (this.userCanaryUrls.length > 0) {
      this.canaryUrls = effectiveUrls;
    }

    // Step 3: add effective URLs to bypass list so they skip the obfuscation
    // pipeline (REQ 1.8)
    for (const url of effectiveUrls) {
      this.bypassManager.addRule(url);
    }

    let failureCount = 0;

    try {
      // Step 4: fetch each URL and record results
      for (let i = 0; i < effectiveUrls.length; i++) {
        const url = effectiveUrls[i];
        const result = await this._fetchWithTimeout(url, this.fetchTimeoutMs);
        this.latestResults.set(url, result);

        // Inject active signal into DpiDetector (REQ 1.4)
        this.dpiDetector.recordActiveProbe(result);

        // Step 5: update consecutive failure counts
        if (result.connectionFailed) {
          failureCount++;
          // Track failures against the user URL (not the effective/fallback URL)
          const userUrl = this.userCanaryUrls[i];
          if (userUrl && this._isValidCanaryUrl(userUrl)) {
            const prev = this.consecutiveFailures.get(userUrl) ?? 0;
            this.consecutiveFailures.set(userUrl, prev + 1);
          } else {
            // Track failures for hardwired URLs too
            const prev = this.consecutiveFailures.get(url) ?? 0;
            this.consecutiveFailures.set(url, prev + 1);
          }
        } else {
          // Reset failure count on success
          const userUrl = this.userCanaryUrls[i];
          if (userUrl && this._isValidCanaryUrl(userUrl)) {
            this.consecutiveFailures.set(userUrl, 0);
          } else {
            this.consecutiveFailures.set(url, 0);
          }
        }
      }
    } finally {
      // Step 6: always remove bypass rules, even on error (REQ 1.8)
      for (const url of effectiveUrls) {
        this.bypassManager.removeRule(url);
      }
    }

    // Step 7: update cycle metadata
    this.lastCycleAt = Date.now();
    this.lastCycleFailureCount = failureCount;
  }

  /**
   * Fetch a URL with an AbortController-based timeout.
   *
   * - On success (2xx–5xx): records TTFB, tlsSuccess, httpStatus (REQ 1.3, 1.9)
   * - On AbortError (timeout): connectionFailed = true, ttfbMs = timeoutMs (REQ 1.10)
   * - On TypeError (network error): connectionFailed = true (REQ 1.10)
   */
  private async _fetchWithTimeout(url: string, timeoutMs: number): Promise<ProbeResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const t0 = performance.now();

    try {
      const response = await fetch(url, { signal: controller.signal });
      const ttfbMs = performance.now() - t0;

      return {
        url,
        ttfbMs,
        tlsSuccess: url.startsWith('https://'),
        connectionFailed: false,
        httpStatus: response.status,
        timestamp: Date.now(),
      };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        // Timeout — treat as blocked (REQ 1.10)
        return {
          url,
          ttfbMs: timeoutMs,
          tlsSuccess: false,
          connectionFailed: true,
          httpStatus: null,
          timestamp: Date.now(),
        };
      }

      // TypeError or other network error (REQ 1.10)
      const ttfbMs = performance.now() - t0;
      return {
        url,
        ttfbMs,
        tlsSuccess: false,
        connectionFailed: true,
        httpStatus: null,
        timestamp: Date.now(),
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _instance: CensorshipProbe | null = null;

/**
 * Returns the singleton CensorshipProbe instance.
 * Throws if the instance has not been initialized yet.
 */
export function getCensorshipProbe(): CensorshipProbe {
  if (!_instance) {
    throw new Error(
      'CensorshipProbe singleton has not been initialized. ' +
      'Call resetCensorshipProbe() with dependencies first, or construct one manually.',
    );
  }
  return _instance;
}

/**
 * Replaces (or clears) the singleton instance.
 * Pass `null` to clear; pass a pre-constructed instance to set.
 * Used by background.ts initialization and by tests.
 */
export function resetCensorshipProbe(instance: CensorshipProbe | null = null): void {
  _instance = instance;
}
