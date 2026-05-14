export type EvasionState = 0x01 | 0x02 | 0x03;

export interface ProbeResult {
  url: string;
  ttfbMs: number;
  tlsSuccess: boolean;
  connectionFailed: boolean;
  httpStatus: number | null;
  timestamp: number;
}

export type CanaryUrlStatus = 'active' | 'fallback' | 'invalid';

export interface CanaryUrlEntry {
  url: string;               // The URL string (may be user-supplied or hardwired)
  isUserDefined: boolean;    // true = user added this, false = hardwired default
  status: CanaryUrlStatus;   // 'active' | 'fallback' | 'invalid'
  consecutiveFailures: number; // how many consecutive cycles this URL has failed
}

export interface CensorshipProbeConfig {
  canaryUrls: string[];
  probeIntervalMs: number;
  fetchTimeoutMs: number;
  enabled: boolean;
  userCanaryUrls?: string[];
}

export type ChunkIntensity = 'mild' | 'aggressive';

export interface ConnectionOutcome {
  state: EvasionState;
  result: 'success' | 'failure';
  latencyMs: number;
  timestamp: number;
}

export interface StateStats {
  successRate: number;
  totalOutcomes: number;
  successCount: number;
}

export interface EvaluatorState {
  active: boolean;
  lastGradientUpdateAt: number | null;
  perStateStats: Record<EvasionState, StateStats>;
}

export const EVASION_STATE = {
  SPLIT: 0x01 as EvasionState,
  DISORDER: 0x02 as EvasionState,
  CHAFF: 0x03 as EvasionState,
} as const;

export interface ProxyConfig {
  mode: 'fixed_servers' | 'pac_script';
  loopbackHost: string;
  loopbackPort: number;
  bypassList: string[];
}

export interface NetworkMetrics {
  latencyMs: number;
  bandwidthBps: number;
  packetLossRate: number;
  dpiDetectionScore: number;
}

export interface TransitionWeights {
  fromState: EvasionState;
  toState: EvasionState;
  weight: number;
}

export type TransitionMatrix = number[][];

export interface EvasionTelemetry {
  nodeId: string;
  timestamp: number;
  activeState: EvasionState;
  transitionWeights: TransitionWeights[];
  detectionScore: number;
  bandwidthEstimateBps: number;
  packetsProcessed: number;
  averageLatencyMs: number;
}

export interface WasmProcessingResult {
  success: boolean;
  outputPointer: number;
  outputLength: number;
  appliedState: EvasionState;
  processingTimeMs: number;
  error?: string;
}

export interface PerformanceLimits {
  maxLatencyOverheadMs: number;
  maxMemoryMb: number;
}

export interface ExtensionConfig {
  enabled: boolean;
  proxyConfig: ProxyConfig;
  bypassList: string[];
  meshEnabled: boolean;
  performanceLimits: PerformanceLimits;
}

export type MeshOperationMode = 'connected' | 'degraded' | 'standalone';

export const MEMORY_LIMIT_EXCEEDED = 'MEMORY_LIMIT_EXCEEDED' as const;
export const COLD_START_BYPASS = 'COLD_START_BYPASS' as const;

export const DEFAULT_TRANSITION_MATRIX: TransitionMatrix = [
  [1/3, 1/3, 1/3],
  [1/3, 1/3, 1/3],
  [1/3, 1/3, 1/3],
];

export const DEFAULT_CONFIG: ExtensionConfig = {
  enabled: true,
  proxyConfig: {
    mode: 'fixed_servers',
    loopbackHost: '127.0.0.1',
    loopbackPort: 8877,
    bypassList: [
      'localhost',
      '127.0.0.1',
      '<local>',
      'detracker.endev.us',
      'ws.detracker.us',
      'ws.tribr.us',
      'swarm.detracker.org',
      'detracker-fallback.fly.dev'
    ],
  },
  bypassList: [],
  meshEnabled: true,
  performanceLimits: {
    maxLatencyOverheadMs: 15,
    maxMemoryMb: 120,
  },
};
