import type { ProbeResult } from './types.js';

/**
 * DPI Detector — Heuristic surveillance signal aggregator
 *
 * Estimates the probability that the current network path includes a
 * Deep Packet Inspection middlebox, based on observable anomalies in
 * the browser's network behaviour.
 *
 * This module does NOT make outbound probe requests. It passively observes
 * the timing and error patterns of requests that the browser already makes,
 * and aggregates them into a single dpiDetectionScore ∈ [0.0, 1.0].
 *
 * Signal sources (from the threat model analysis):
 *
 *   Signal 1 — Selective connection failures
 *     TCP RST or immediate TLS abort on HTTPS requests while non-TLS
 *     traffic succeeds. Indicates a middlebox reading the SNI field.
 *
 *   Signal 2 — Latency spikes on TLS handshakes
 *     DPI requires CPU to reassemble and inspect packets. A consistent
 *     latency overhead on TLS connections (vs plain HTTP) suggests
 *     inline inspection.
 *
 *   Signal 3 — Latency jitter (variance)
 *     Erratic latency on otherwise stable connections. DPI processing
 *     time is non-deterministic and introduces measurable jitter.
 *
 *   Signal 4 — Forced reassembly fingerprint
 *     When DISORDER tactic (small/fragmented packets) is active but
 *     the server receives them perfectly ordered, a middlebox is
 *     reassembling them. Detected as unexpectedly low error rate
 *     during DISORDER mode (the "cleaner" is working).
 *
 *   Signal 5 — Mesh peer intelligence
 *     Aggregated detectionScore from peers on the same ISP/region.
 *     The most reliable signal — peers that are already being blocked
 *     warn the local node before it is affected.
 */

export interface DpiSignals {
  /** Ratio of failed HTTPS connections to total HTTPS connections [0,1] */
  tlsFailureRate: number;
  /** Average latency overhead on TLS vs baseline (ms) */
  tlsLatencyOverheadMs: number;
  /** Coefficient of variation of recent latency samples (jitter) */
  latencyJitter: number;
  /** Score received from mesh peers on the same region [0,1] */
  meshPeerScore: number;
  /** Whether DISORDER tactic is producing suspiciously clean delivery */
  forcedReassemblyHint: boolean;
  /** Ratio of failed active probes to total active probes in current cycle [0,1] */
  probeSignal: number;
}

export interface DpiDetectorSnapshot {
  score: number;           // Aggregated score [0.0, 1.0]
  level: ThreatLevel;
  signals: DpiSignals;
  dominantSignal: keyof DpiSignals | null;
  updatedAt: number;       // Unix ms
}

export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

// ── Thresholds ───────────────────────────────────────────────────────────────

/** Score boundaries for each threat level */
const LEVEL_THRESHOLDS: Record<ThreatLevel, number> = {
  none:     0.0,
  low:      0.15,
  medium:   0.35,
  high:     0.60,
  critical: 0.80,
};

/** Signal weights — must sum to 1.0 */
const SIGNAL_WEIGHTS = {
  tlsFailureRate:         0.30,  // Strongest individual signal
  tlsLatencyOverheadMs:   0.20,
  latencyJitter:          0.15,
  meshPeerScore:          0.25,  // Collective intelligence
  forcedReassemblyHint:   0.10,
} as const;

// ── Rolling window config ─────────────────────────────────────────────────────

const LATENCY_WINDOW_SIZE = 30;   // Keep last N latency samples
const BASELINE_WINDOW_SIZE = 10;  // Samples used to establish baseline
const DECAY_FACTOR = 0.92;        // Score decays toward 0 when no new signals

// ── Internal state ────────────────────────────────────────────────────────────

interface RequestRecord {
  url: string;
  isTls: boolean;
  latencyMs: number;
  failed: boolean;
  state: number;  // EvasionState active during this request
  timestamp: number;
}

export class DpiDetector {
  private recentRequests: RequestRecord[] = [];
  private latencySamples: number[] = [];
  private baselineSamples: number[] = [];
  private meshPeerScore: number = 0;
  private currentScore: number = 0;
  private lastSnapshot: DpiDetectorSnapshot | null = null;

  // Active probe counters — reset at the start of each CensorshipProbe cycle
  private activeProbeTotal: number = 0;
  private activeProbeFailures: number = 0;
  private activeProbeHighLatency: number = 0;

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Records the outcome of a single network request.
   * Called by handleNetworkStream after each request completes.
   */
  recordRequest(
    url: string,
    latencyMs: number,
    failed: boolean,
    activeState: number,
  ): void {
    const isTls = url.startsWith('https://') || url.startsWith('wss://');

    this.recentRequests.push({
      url,
      isTls,
      latencyMs,
      failed,
      state: activeState,
      timestamp: Date.now(),
    });

    // Keep a rolling window of the last 100 requests
    if (this.recentRequests.length > 100) {
      this.recentRequests.shift();
    }

    // Track latency samples separately for jitter calculation
    this.latencySamples.push(latencyMs);
    if (this.latencySamples.length > LATENCY_WINDOW_SIZE) {
      this.latencySamples.shift();
    }

    // Establish baseline from the first N successful non-TLS requests
    if (!failed && !isTls && this.baselineSamples.length < BASELINE_WINDOW_SIZE) {
      this.baselineSamples.push(latencyMs);
    }

    this._recompute();
  }

  /**
   * Injects the aggregated score from mesh peers.
   * Called when telemetry is received from a peer node.
   */
  updateMeshScore(peerScore: number): void {
    // Weighted average: new peer score has 40% influence
    this.meshPeerScore = this.meshPeerScore * 0.6 + peerScore * 0.4;
    this._recompute();
  }

  /**
   * Records the outcome of an active canary probe.
   * Called by CensorshipProbe after each URL fetch attempt.
   * Increments internal counters and triggers an immediate recompute.
   */
  recordActiveProbe(result: ProbeResult): void {
    this.activeProbeTotal++;
    if (result.connectionFailed) {
      this.activeProbeFailures++;
    }
    // High-latency threshold: > 2000 ms TTFB is suspicious (REQ 2.3)
    if (result.ttfbMs > 2000) {
      this.activeProbeHighLatency++;
    }
    this._recompute();
  }

  /**
   * Resets all active probe counters to zero.
   * Called by CensorshipProbe at the start of each new measurement cycle (REQ 2.7).
   */
  resetProbeCounters(): void {
    this.activeProbeTotal = 0;
    this.activeProbeFailures = 0;
    this.activeProbeHighLatency = 0;
  }

  /**
   * Returns the current aggregated DPI detection score [0.0, 1.0].
   */
  getScore(): number {
    return this.currentScore;
  }

  /**
   * Returns the current threat level label.
   */
  getLevel(): ThreatLevel {
    return scoreToLevel(this.currentScore);
  }

  /**
   * Returns a full snapshot of the current detection state.
   */
  getSnapshot(): DpiDetectorSnapshot {
    if (this.lastSnapshot) return this.lastSnapshot;
    return {
      score: 0,
      level: 'none',
      signals: this._computeSignals(),
      dominantSignal: null,
      updatedAt: Date.now(),
    };
  }

  /**
   * Applies score decay — call periodically (e.g. every 5s) so the score
   * drifts back toward 0 when no new anomalies are observed.
   */
  decay(): void {
    this.currentScore = this.currentScore * DECAY_FACTOR;
    if (this.currentScore < 0.01) this.currentScore = 0;
    this._updateSnapshot(this._computeSignals());
  }

  // ── Private ─────────────────────────────────────────────────────────────────

  private _recompute(): void {
    const signals = this._computeSignals();
    const raw = this._aggregate(signals);
    // Smooth: new score can only rise quickly, falls slowly
    this.currentScore = raw > this.currentScore
      ? raw
      : this.currentScore * 0.85 + raw * 0.15;
    this.currentScore = Math.min(1.0, Math.max(0.0, this.currentScore));
    this._updateSnapshot(signals);
  }

  private _computeSignals(): DpiSignals {
    return {
      tlsFailureRate:        this._tlsFailureRate(),
      tlsLatencyOverheadMs:  this._tlsLatencyOverhead(),
      latencyJitter:         this._latencyJitter(),
      meshPeerScore:         this.meshPeerScore,
      forcedReassemblyHint:  this._forcedReassemblyHint(),
      probeSignal:           this.activeProbeTotal > 0
        ? this.activeProbeFailures / this.activeProbeTotal
        : 0,
    };
  }

  private _aggregate(signals: DpiSignals): number {
    // Normalize each signal to [0,1] before weighting
    const normalized = {
      tlsFailureRate:        clamp(signals.tlsFailureRate, 0, 1),
      // Overhead > 50ms is suspicious; > 200ms is near-certain DPI
      tlsLatencyOverheadMs:  clamp(signals.tlsLatencyOverheadMs / 200, 0, 1),
      // CV > 1.0 is very high jitter
      latencyJitter:         clamp(signals.latencyJitter, 0, 1),
      meshPeerScore:         clamp(signals.meshPeerScore, 0, 1),
      forcedReassemblyHint:  signals.forcedReassemblyHint ? 1.0 : 0.0,
    };

    let passiveScore = 0;
    for (const key of Object.keys(SIGNAL_WEIGHTS) as Array<keyof typeof SIGNAL_WEIGHTS>) {
      passiveScore += normalized[key] * SIGNAL_WEIGHTS[key];
    }

    // Blend passive score (×0.60) with capped probe contribution (max 0.40)
    // per REQ 2.5: probe contribution must not exceed 40% of total score.
    // rawProbeScore = clamp(probeSignal, 0, 1) * 0.5 + clamp(highLatencyRatio, 0, 1) * 0.5
    const highLatencyRatio = this.activeProbeTotal > 0
      ? this.activeProbeHighLatency / this.activeProbeTotal
      : 0;
    const rawProbeScore =
      clamp(signals.probeSignal, 0, 1) * 0.5 +
      clamp(highLatencyRatio, 0, 1) * 0.5;
    const probeContribution = Math.min(rawProbeScore, 0.40);

    return passiveScore * 0.60 + probeContribution;
  }

  private _updateSnapshot(signals: DpiSignals): void {
    const dominantSignal = this._dominantSignal(signals);
    this.lastSnapshot = {
      score: this.currentScore,
      level: scoreToLevel(this.currentScore),
      signals,
      dominantSignal,
      updatedAt: Date.now(),
    };
  }

  /** Signal 1: ratio of failed TLS connections */
  private _tlsFailureRate(): number {
    const tls = this.recentRequests.filter(r => r.isTls);
    if (tls.length < 3) return 0; // Not enough data
    const failed = tls.filter(r => r.failed).length;
    return failed / tls.length;
  }

  /** Signal 2: average latency overhead of TLS vs baseline */
  private _tlsLatencyOverhead(): number {
    if (this.baselineSamples.length < 3) return 0;
    const baseline = mean(this.baselineSamples);
    const tlsSamples = this.recentRequests
      .filter(r => r.isTls && !r.failed)
      .slice(-10)
      .map(r => r.latencyMs);
    if (tlsSamples.length < 3) return 0;
    const tlsMean = mean(tlsSamples);
    return Math.max(0, tlsMean - baseline);
  }

  /** Signal 3: coefficient of variation of recent latency (jitter) */
  private _latencyJitter(): number {
    if (this.latencySamples.length < 5) return 0;
    const m = mean(this.latencySamples);
    if (m === 0) return 0;
    const sd = stddev(this.latencySamples, m);
    return sd / m; // Coefficient of variation
  }

  /**
   * Signal 4: when DISORDER tactic is active, a suspiciously low error rate
   * suggests a middlebox is reassembling fragmented packets.
   * Heuristic: if DISORDER has been active for >10 requests with 0 failures,
   * something upstream is "cleaning" the traffic.
   */
  private _forcedReassemblyHint(): boolean {
    const disorderRequests = this.recentRequests
      .filter(r => r.state === 0x02)
      .slice(-15);
    if (disorderRequests.length < 10) return false;
    const failureRate = disorderRequests.filter(r => r.failed).length / disorderRequests.length;
    // In DISORDER mode we expect some delivery issues; zero failures is suspicious
    return failureRate === 0 && disorderRequests.length >= 10;
  }

  /** Returns the signal contributing most to the current score */
  private _dominantSignal(signals: DpiSignals): keyof DpiSignals | null {
    const contributions: Array<[keyof DpiSignals, number]> = [
      ['tlsFailureRate',        clamp(signals.tlsFailureRate, 0, 1)        * SIGNAL_WEIGHTS.tlsFailureRate],
      ['tlsLatencyOverheadMs',  clamp(signals.tlsLatencyOverheadMs / 200, 0, 1) * SIGNAL_WEIGHTS.tlsLatencyOverheadMs],
      ['latencyJitter',         clamp(signals.latencyJitter, 0, 1)         * SIGNAL_WEIGHTS.latencyJitter],
      ['meshPeerScore',         clamp(signals.meshPeerScore, 0, 1)         * SIGNAL_WEIGHTS.meshPeerScore],
      ['forcedReassemblyHint',  signals.forcedReassemblyHint ? SIGNAL_WEIGHTS.forcedReassemblyHint : 0],
      ['probeSignal',           clamp(signals.probeSignal, 0, 1)           * 0.40],
    ];
    contributions.sort((a, b) => b[1] - a[1]);
    return contributions[0][1] > 0.01 ? contributions[0][0] : null;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v));
}

function mean(arr: number[]): number {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr: number[], m: number): number {
  const variance = arr.reduce((acc, v) => acc + (v - m) ** 2, 0) / arr.length;
  return Math.sqrt(variance);
}

export function scoreToLevel(score: number): ThreatLevel {
  if (score >= LEVEL_THRESHOLDS.critical) return 'critical';
  if (score >= LEVEL_THRESHOLDS.high)     return 'high';
  if (score >= LEVEL_THRESHOLDS.medium)   return 'medium';
  if (score >= LEVEL_THRESHOLDS.low)      return 'low';
  return 'none';
}

// ── Singleton ─────────────────────────────────────────────────────────────────

let _instance: DpiDetector | null = null;

export function getDpiDetector(): DpiDetector {
  if (!_instance) _instance = new DpiDetector();
  return _instance;
}

export function resetDpiDetector(): void {
  _instance = null;
}

// ── Human-readable signal labels ──────────────────────────────────────────────

export const SIGNAL_LABELS: Record<keyof DpiSignals, string> = {
  tlsFailureRate:        'Selective TLS failures',
  tlsLatencyOverheadMs:  'TLS handshake overhead',
  latencyJitter:         'Latency jitter (DPI CPU)',
  meshPeerScore:         'Mesh peer intelligence',
  forcedReassemblyHint:  'Forced packet reassembly',
  probeSignal:           'Active canary probe failures',
};
