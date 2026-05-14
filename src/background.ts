/**
 * PPO Background Service Worker — Layer 1 entry point.
 *
 * Responsibilities (Task 9.1):
 *   - Lazy-init singleton for the Wasm instance (getWasmInstance)
 *   - Cold start measurement with telemetry warning if > 800ms
 *   - chrome.alarms keep-alive (sw-keepalive, 20-second interval)
 *   - chrome.proxy fixed_servers configuration with strict bypass list
 *   - WebRTC / DNS leak prevention via proxy mode
 *
 * Responsibilities (Task 9.2):
 *   - FIFO request queue with max capacity of 50 during cold start
 *   - Enqueue incoming requests while wasmInstance is null
 *   - Pass overflow requests (> 50) with COLD_START_BYPASS flag
 *   - Drain queue in FIFO order after Wasm init completes
 *
 * Responsibilities (Task 10.2):
 *   - GC scheduling: when activeRequests drops to 0, schedule triggerGC after 100ms
 *   - GC cancellation: cancel pending GC timeout when a new request arrives
 *   - Degraded mode: if MEMORY_LIMIT_EXCEEDED, pass chunks without obfuscation
 *   - Auto-recovery: re-enable obfuscation when memory drops below 120MB threshold
 *
 * Requirements: 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 11.1, 11.5, 12.3, 12.4
 */

import { createWasmBridge, WasmNetworkBridge } from './bridge.js';
import { getMarkovFSM } from './markov_fsm.js';
import { getMeshNode } from './mesh_node.js';
import { createBypassManager, BypassManager } from './bypass_manager.js';
import { getDpiDetector } from './dpi_detector.js';
import { CensorshipProbe, resetCensorshipProbe } from './censorship_probe.js';
import { ChunkRandomizer, getChunkRandomizer, resetChunkRandomizer } from './chunk_randomizer.js';
import { StrategyEvaluator, getStrategyEvaluator, resetStrategyEvaluator } from './strategy_evaluator.js';
import {
  ProxyConfig,
  EvasionState,
  DEFAULT_CONFIG,
  COLD_START_BYPASS,
} from './types.js';

// ---------------------------------------------------------------------------
// HTTP Host Fragmenter (REQ 3.1, 3.2, 3.3, 3.4, 3.5, 3.7, 3.8, 8.4)
// ---------------------------------------------------------------------------

/**
 * HTTP/1.1 method tokens used to identify HTTP requests.
 * REQ 3.7
 */
const HTTP_METHOD_TOKENS = [
  'GET ',
  'POST ',
  'PUT ',
  'DELETE ',
  'HEAD ',
  'OPTIONS ',
  'PATCH ',
  'CONNECT ',
] as const;

/**
 * Splits an HTTP/1.1 request buffer at a stochastic offset within the Host
 * header value, producing two fragments that together reconstruct the original
 * request when concatenated.
 *
 * Algorithm:
 *   0. Guard: if `buffer[0] === 0x16` (TLS ClientHello), return `[buffer]` immediately (REQ 8.4).
 *   1. Decode the buffer as ASCII text.
 *   2. If the text does not start with a recognised HTTP/1.1 method token, return `[buffer]` (REQ 3.7).
 *   3. Locate the `Host:` header (case-insensitive); return `[buffer]` if absent (REQ 3.4).
 *   4. Find the start of the host value (skip optional leading space) and the end of the line.
 *   5. If the host value is shorter than 2 bytes, return `[buffer]` (REQ 3.5).
 *   6. Choose a stochastic split offset `k ∈ [1, hostValueLen - 1]` via `crypto.getRandomValues` (REQ 3.2).
 *   7. Return `[buffer.slice(0, valueStart + k), buffer.slice(valueStart + k)]` (REQ 3.3, 3.8).
 *
 * This is a pure function — the input buffer is never modified.
 *
 * REQ 3.1, 3.2, 3.3, 3.4, 3.5, 3.7, 3.8, 8.4
 */
export function fragmentHttpHost(buffer: Uint8Array): Uint8Array[] {
  // Guard 0: TLS ClientHello — return passthrough immediately (REQ 8.4)
  if (buffer[0] === 0x16) {
    return [buffer];
  }

  // Step 1: decode as ASCII text
  const text = new TextDecoder('ascii', { fatal: false }).decode(buffer);

  // Step 2: check for HTTP/1.1 method token (REQ 3.7)
  const startsWithMethod = HTTP_METHOD_TOKENS.some((token) => text.startsWith(token));
  if (!startsWithMethod) {
    return [buffer];
  }

  // Step 3: locate "Host:" header (case-insensitive) (REQ 3.1)
  const lowerText = text.toLowerCase();
  const hostHeaderIdx = lowerText.indexOf('host:');
  if (hostHeaderIdx === -1) {
    return [buffer]; // no Host header (REQ 3.4)
  }

  // Step 4: find value start (skip "host:" and optional space)
  let valueStart = hostHeaderIdx + 5; // len("host:")
  while (valueStart < text.length && text[valueStart] === ' ') {
    valueStart++;
  }

  // Step 5: find line end (\r\n or \n)
  let lineEnd = text.indexOf('\r\n', valueStart);
  if (lineEnd === -1) {
    lineEnd = text.indexOf('\n', valueStart);
  }
  if (lineEnd === -1) {
    lineEnd = buffer.length;
  }

  const hostValueLen = lineEnd - valueStart;

  // Step 6: check minimum length (REQ 3.5)
  if (hostValueLen < 2) {
    return [buffer];
  }

  // Step 7: choose stochastic split offset k ∈ [1, hostValueLen - 1] (REQ 3.2)
  const rng = new Uint32Array(1);
  crypto.getRandomValues(rng);
  const k = 1 + (rng[0] % (hostValueLen - 1));

  // Step 8: split at (valueStart + k) (REQ 3.3, 3.8)
  const splitPoint = valueStart + k;
  return [buffer.slice(0, splitPoint), buffer.slice(splitPoint)];
}

// ---------------------------------------------------------------------------
// Module-level singletons
// ---------------------------------------------------------------------------

/** Cached Wasm bridge instance — null until first call to getWasmInstance(). */
let _wasmInstance: WasmNetworkBridge | null = null;

/** Promise that resolves when the Wasm instance is ready (prevents concurrent inits). */
let _wasmInitPromise: Promise<WasmNetworkBridge> | null = null;

/** Bypass manager singleton. */
let _bypassManager: BypassManager | null = null;

/** CensorshipProbe singleton — null until initialize() Step 8 runs. */
let _censorshipProbe: CensorshipProbe | null = null;

/** Whether HTTP Host Fragmenter is enabled (default: false, REQ 8.2). */
export let _hostFragmenterEnabled: boolean = false;

/** Whether ChunkRandomizer is enabled (default: false, REQ 8.2). */
export let _chunkRandomizerEnabled: boolean = false;

/** Whether StrategyEvaluator is enabled (default: false, REQ 8.2). */
export let _strategyEvaluatorEnabled: boolean = false;

/** Timestamp of the last mesh telemetry received (for StrategyEvaluator mesh deferral). */
export let _lastMeshTelemetryAt: number = 0;

/** Whether a manual FORCE_TACTIC override is currently active. */
export let manualOverrideActive: boolean = false;

/** Accessor for CensorshipProbe singleton. */
export function getCensorshipProbe(): CensorshipProbe | null {
  return _censorshipProbe;
}

/**
 * Accessor for ChunkRandomizer singleton.
 * Delegates to the chunk_randomizer.ts module singleton.
 * REQ 8.1, 8.2
 */
export { getChunkRandomizer, getStrategyEvaluator };

// ---------------------------------------------------------------------------
// Cold start request queue (REQ 2.3, 2.4, 2.5)
// ---------------------------------------------------------------------------

/** Maximum number of requests that can be queued during cold start. */
export const COLD_START_QUEUE_MAX = 50;

/**
 * A pending request waiting for the Wasm instance to become available.
 * Stored in the FIFO queue during cold start.
 */
export interface QueuedRequest {
  data: Uint8Array;
  resolve: (result: Uint8Array | typeof COLD_START_BYPASS) => void;
  reject: (err: Error) => void;
}

/** FIFO queue of requests received while Wasm is still initialising. */
export const _coldStartQueue: QueuedRequest[] = [];

/**
 * Enqueues a request if Wasm is still initialising, or processes it
 * immediately if Wasm is ready.
 *
 * Behaviour:
 *   - Wasm ready → process immediately via the bridge
 *   - Wasm initialising, queue < 50 → enqueue and return a Promise (REQ 2.3)
 *   - Wasm initialising, queue >= 50 → return COLD_START_BYPASS immediately (REQ 2.4)
 *
 * REQ 2.3, 2.4, 2.5
 */
export function enqueueOrProcess(
  data: Uint8Array,
): Promise<Uint8Array | typeof COLD_START_BYPASS> {
  // Fast path — Wasm is already initialised
  if (_wasmInstance !== null) {
    return _processWithBridge(_wasmInstance, data);
  }

  // Overflow path — queue is full, bypass without obfuscation (REQ 2.4)
  if (_coldStartQueue.length >= COLD_START_QUEUE_MAX) {
    return Promise.resolve(COLD_START_BYPASS);
  }

  // Enqueue path — add to FIFO queue and return a deferred promise (REQ 2.3)
  return new Promise<Uint8Array | typeof COLD_START_BYPASS>((resolve, reject) => {
    _coldStartQueue.push({ data, resolve, reject });
  });
}

/**
 * Processes all queued requests in FIFO order using the now-ready Wasm bridge.
 * Called immediately after Wasm initialisation completes.
 *
 * REQ 2.5
 */
export function drainQueue(bridge: WasmNetworkBridge): void {
  // Process items in FIFO order (shift from front)
  while (_coldStartQueue.length > 0) {
    const item = _coldStartQueue.shift()!;
    _processWithBridge(bridge, item.data)
      .then(item.resolve)
      .catch(item.reject);
  }
}

/**
 * Internal helper: allocates a buffer, writes data, processes it, reads the
 * result, and frees both buffers. Returns the processed bytes.
 */
async function _processWithBridge(
  bridge: WasmNetworkBridge,
  data: Uint8Array,
): Promise<Uint8Array> {
  const ptr = bridge.allocateBuffer(data.byteLength);
  bridge.writeBuffer(ptr, data);
  const resultPtr = bridge.processBytes(ptr, data.byteLength, 0x01);
  const resultBuf = bridge.readBuffer(resultPtr, data.byteLength);
  bridge.freeBuffer(ptr);
  bridge.freeBuffer(resultPtr);
  return new Uint8Array(resultBuf);
}

// ---------------------------------------------------------------------------
// Wasm lazy-init singleton (REQ 1.5, 2.2)
// ---------------------------------------------------------------------------

/**
 * Returns the cached Wasm bridge instance, initialising it on the first call.
 *
 * Cold start duration is measured and logged. If it exceeds 800ms a telemetry
 * warning is emitted (REQ 2.6, 2.7).
 *
 * Concurrent callers share the same init promise so the module is only loaded
 * once even if multiple requests arrive during cold start.
 */
export async function getWasmInstance(): Promise<WasmNetworkBridge> {
  // Fast path — already initialised
  if (_wasmInstance !== null) {
    return _wasmInstance;
  }

  // Serialise concurrent initialisations
  if (_wasmInitPromise !== null) {
    return _wasmInitPromise;
  }

  _wasmInitPromise = _initWasm();
  return _wasmInitPromise;
}

async function _initWasm(): Promise<WasmNetworkBridge> {
  const t0 = performance.now();

  try {
    // In a real extension the Wasm binary would be fetched and instantiated here.
    // For the current implementation the WasmBridge provides the in-process
    // simulation that is used by all other components and tests.
    const bridge = createWasmBridge();

    // Attempt to load the real Wasm module when running inside Chrome.
    // MV3 CSP requires streaming compilation — instantiateStreaming(fetch(...))
    // is allowed with 'wasm-unsafe-eval'; instantiate(ArrayBuffer) is not.
    // The Go Wasm runtime (wasm_exec.js) must be loaded via importScripts
    // before this point so that globalThis.Go is available.
    if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
      try {
        // Load wasm_exec.js shim if not already present (provides globalThis.Go)
        if (typeof (globalThis as any).Go === 'undefined') {
          importScripts(chrome.runtime.getURL('wasm_exec.js'));
        }

        const go = new (globalThis as any).Go();
        const wasmUrl = chrome.runtime.getURL('ppo.wasm');

        // instantiateStreaming is the only form allowed by MV3 CSP with wasm-unsafe-eval.
        // We pass go.importObject so the Go runtime's host imports are satisfied.
        const result = await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);

        // Run the Go program — this starts the runtime and blocks in select{}
        // inside main.go, keeping the exported JS functions alive.
        go.run(result.instance);
      } catch (wasmErr) {
        // Non-fatal: fall back to the in-process bridge simulation
        console.warn('[PPO] Wasm module load failed, using simulation bridge:', wasmErr);
      }
    }

    const coldStartMs = performance.now() - t0;

    // REQ 2.6 — always log cold start duration
    console.log(`[PPO] Wasm cold start: ${coldStartMs.toFixed(2)}ms`);

    // REQ 2.7 — emit telemetry warning if cold start exceeds 800ms
    if (coldStartMs > 800) {
      console.warn('[PPO] Cold start exceeded threshold', {
        event: 'cold_start_slow',
        durationMs: coldStartMs,
        thresholdMs: 800,
      });
    }

    _wasmInstance = bridge;
    // REQ 2.5 — drain any requests that arrived during cold start
    drainQueue(bridge);
    return bridge;
  } catch (err) {
    // Reset so the next call can retry
    _wasmInitPromise = null;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Bypass manager singleton
// ---------------------------------------------------------------------------

export function getBypassManager(): BypassManager {
  if (_bypassManager === null) {
    _bypassManager = createBypassManager(DEFAULT_CONFIG.bypassList);
  }
  return _bypassManager;
}

// ---------------------------------------------------------------------------
// chrome.proxy configuration (REQ 1.5, 1.6, 2.6)
// ---------------------------------------------------------------------------

/**
 * Registers chrome.proxy rules.
 *
 * Mode `direct` lets Chrome navigate normally — no loopback proxy is needed
 * because the Service Worker intercepts streams directly via the Fetch API.
 * The `fixed_servers` mode from the spec assumed an external SOCKS5 node that
 * does not exist in this implementation; using it blocks all navigation.
 *
 * REQ 1.5, 1.6, 2.6
 */
export function registerProxyRules(config: ProxyConfig = DEFAULT_CONFIG.proxyConfig): void {
  if (typeof chrome === 'undefined' || !chrome.proxy) {
    // Not running inside Chrome (e.g. unit tests) — skip silently
    return;
  }

  let proxyConfig: chrome.proxy.ProxyConfig;

  if (config.mode === 'fixed_servers') {
    proxyConfig = {
      mode: 'fixed_servers',
      rules: {
        singleProxy: {
          scheme: 'http',
          host: config.loopbackHost,
          port: config.loopbackPort,
        },
        // Bypass list ensures critical infrastructure (like DeTracker signaling) 
        // is never routed through the PPO pipeline. (REQ 1.6)
        bypassList: config.bypassList,
      },
    };
  } else {
    // Fallback or explicit 'direct' mode
    proxyConfig = { mode: 'direct' };
  }

  chrome.proxy.settings.set(
    { value: proxyConfig, scope: 'regular' },
    () => {
      if (chrome.runtime.lastError) {
        console.error('[PPO] Failed to set proxy rules:', chrome.runtime.lastError.message);
      } else {
        console.log(
          `[PPO] Proxy rules registered (${config.mode} mode)`,
          config.mode === 'fixed_servers' ? `→ ${config.loopbackHost}:${config.loopbackPort}` : ''
        );
      }
    }
  );
}

// ---------------------------------------------------------------------------
// chrome.alarms keep-alive (REQ 2.1)
// ---------------------------------------------------------------------------

const KEEPALIVE_ALARM_NAME = 'sw-keepalive';

/**
 * Registers the keep-alive alarm so Chrome does not suspend the Service Worker
 * during active browsing sessions.
 *
 * The alarm fires every 20 seconds (periodInMinutes = 20/60).
 * REQ 2.1
 */
export function registerKeepAliveAlarm(): void {
  if (typeof chrome === 'undefined' || !chrome.alarms) {
    return;
  }

  chrome.alarms.create(KEEPALIVE_ALARM_NAME, {
    periodInMinutes: 20 / 60, // 20 seconds expressed in minutes
  });

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === KEEPALIVE_ALARM_NAME) {
      // Accessing a chrome API is sufficient to keep the SW alive
      void chrome.storage.session.get(null);
    }
  });

  console.log('[PPO] Keep-alive alarm registered (interval: 20s)');
}

// ---------------------------------------------------------------------------
// Service Worker initialisation (REQ 1.5, 2.2)
// ---------------------------------------------------------------------------

/**
 * Main initialisation sequence for the Service Worker.
 *
 * Order:
 *   1. Register proxy rules (must happen before any request is processed)
 *   2. Register keep-alive alarm
 *   3. Trigger Wasm cold start (async, non-blocking for proxy/alarm setup)
 *   4. Restore TransitionMatrix from chrome.storage.session and apply to MarkovFSM
 *   5. Wire MeshNode.onMatrixUpdated → MarkovFSM.setTransitionMatrix
 *   6. Wire MeshNode.onTelemetryReceived → MarkovFSM.transition
 *   7. Connect mesh (ensure MeshNode singleton is instantiated and ready)
 *
 * Each step is wrapped in try-catch for graceful fallback: if a step fails,
 * the error is logged and initialisation continues with the next step so the
 * Service Worker never crashes due to a non-critical subsystem failure.
 *
 * Total initialisation duration is measured and logged for monitoring (REQ 2.6).
 *
 * REQ 1.5, 1.6, 2.1, 2.2, 2.6, 10.2, 10.4, 10.7
 */
export async function initialize(): Promise<void> {
  const initStart = performance.now();

  // Step 1 — proxy rules (must happen before any request is processed, REQ 1.5, 1.6)
  try {
    registerProxyRules();
  } catch (err) {
    console.warn('[PPO] initialize: registerProxyRules failed (graceful fallback)', err);
  }

  // Step 2 — keep-alive alarm (REQ 2.1)
  try {
    registerKeepAliveAlarm();
  } catch (err) {
    console.warn('[PPO] initialize: registerKeepAliveAlarm failed (graceful fallback)', err);
  }

  // Step 3 — start Wasm init / cold start (REQ 1.5, 2.2; cold start measurement inside)
  try {
    await getWasmInstance();
  } catch (err) {
    console.warn('[PPO] initialize: getWasmInstance failed (graceful fallback)', err);
  }

  // Step 4 — restore the last known TransitionMatrix from chrome.storage.session
  // and apply it to the MarkovFSM before processing any requests (REQ 10.2, 10.4).
  // This ensures that in standalone mode the FSM continues with the last known matrix.
  let meshNode;
  try {
    meshNode = getMeshNode();
    const restoredMatrix = await meshNode.restoreTransitionWeights();
    getMarkovFSM().setTransitionMatrix(restoredMatrix);
  } catch (err) {
    console.warn('[PPO] initialize: restoreTransitionWeights failed (graceful fallback)', err);
    // Ensure meshNode is available for subsequent steps even if restore failed
    if (!meshNode) {
      try {
        meshNode = getMeshNode();
      } catch {
        // MeshNode unavailable — skip mesh wiring steps
      }
    }
  }

  if (meshNode) {
    // Step 5 — wire MeshNode.onMatrixUpdated → MarkovFSM.setTransitionMatrix (REQ 10.4, 10.7).
    // When the mesh is connected or degraded and receives peer telemetry, the FSM is updated.
    // When the mesh is in standalone mode, no new updates arrive and the FSM keeps the last
    // known matrix — obfuscation continues uninterrupted regardless of mesh mode (REQ 10.5, 10.7).
    try {
      meshNode.onMatrixUpdated((matrix) => {
        try {
          getMarkovFSM().setTransitionMatrix(matrix);
        } catch (err) {
          console.warn('[PPO] initialize: failed to apply updated TransitionMatrix to MarkovFSM', err);
        }
      });
    } catch (err) {
      console.warn('[PPO] initialize: onMatrixUpdated wiring failed (graceful fallback)', err);
    }

    // Step 6 — wire MeshNode.onTelemetryReceived → MarkovFSM.transition (REQ 8.3, 10.7).
    // When peer telemetry arrives, drive an FSM transition using the peer-observed network
    // metrics so the local evasion strategy adapts to conditions seen across the mesh.
    try {
      meshNode.onTelemetryReceived((telemetry) => {
        try {
          getMarkovFSM().transition({
            dpiDetectionScore: telemetry.detectionScore,
            bandwidthBps: telemetry.bandwidthEstimateBps,
            latencyMs: telemetry.averageLatencyMs,
            packetLossRate: 0,
          });
          // Feed mesh peer score into the DPI detector (Signal 5)
          getDpiDetector().updateMeshScore(telemetry.detectionScore);
          // Persist the updated transition weights after the FSM has transitioned (REQ 10.1).
          void meshNode!.persistTransitionWeights(getMarkovFSM().getTransitionProbabilities());
        } catch (err) {
          console.warn('[PPO] initialize: failed to transition MarkovFSM from mesh telemetry', err);
        }
        _globalStats.meshUpdatesReceived++;
          _lastMeshTelemetryAt = Date.now();
      });
    } catch (err) {
      console.warn('[PPO] initialize: onTelemetryReceived wiring failed (graceful fallback)', err);
    }

    // Step 7 — connectMesh: ensure the MeshNode singleton is instantiated and ready.
    // No peer IDs are known at startup, so this is a no-op connection-wise.
    // The singleton is already created above; this step just confirms readiness (REQ 2.2).
    try {
      // getMeshNode() already called above — singleton is ready.
      // Log mesh readiness so monitoring can confirm the mesh subsystem initialised.
      console.log('[PPO] Mesh node ready (nodeId:', meshNode.nodeId, ')');
    } catch (err) {
      console.warn('[PPO] initialize: connectMesh step failed (graceful fallback)', err);
    }
  }

  // Step 8 — initialize advanced evasion components (REQ 8.1, 8.2)
  // Must run AFTER steps 1-7 (existing Wasm + Mesh initialization)
  try {
    const advConfig = typeof chrome !== 'undefined' && chrome.storage
      ? await chrome.storage.session.get([
          'ppo_advanced_evasion_enabled',
          'ppo_probe_enabled',
          'ppo_probe_interval',
          'ppo_canary_urls',
          'ppo_chunk_intensity',
          'ppo_chunk_randomizer_enabled',
          'ppo_host_fragmenter_enabled',
          'ppo_strategy_evaluator_enabled',
        ])
      : {};

    // Initialize CensorshipProbe
    const probe = new CensorshipProbe(
      getDpiDetector(),
      getBypassManager(),
      {
        canaryUrls: advConfig.ppo_canary_urls,
        probeIntervalMs: advConfig.ppo_probe_interval,
        enabled: advConfig.ppo_probe_enabled ?? false,
      },
    );
    _censorshipProbe = probe;
    resetCensorshipProbe(probe);
    if (advConfig.ppo_probe_enabled) {
      probe.start();
    }

    // Initialize ChunkRandomizer
    const randomizer = new ChunkRandomizer({
      intensity: advConfig.ppo_chunk_intensity ?? 'mild',
      enabled: advConfig.ppo_chunk_randomizer_enabled ?? false,
    });
    resetChunkRandomizer(randomizer);
    _chunkRandomizerEnabled = advConfig.ppo_chunk_randomizer_enabled ?? false;

    // Initialize StrategyEvaluator
    const evaluator = new StrategyEvaluator(
      getMarkovFSM(),
      getMeshNode(),
      { enabled: advConfig.ppo_strategy_evaluator_enabled ?? false },
      () => manualOverrideActive,
      () => _lastMeshTelemetryAt,
    );
    resetStrategyEvaluator(evaluator);
    _strategyEvaluatorEnabled = advConfig.ppo_strategy_evaluator_enabled ?? false;

    // Host Fragmenter is a pure function — just set the enabled flag
    _hostFragmenterEnabled = advConfig.ppo_host_fragmenter_enabled ?? false;

    console.log('[PPO] Advanced evasion components initialized');
  } catch (err) {
    console.warn('[PPO] initialize: advanced evasion component init failed (graceful fallback)', err);
  }

  // REQ 2.6 — log total initialisation duration for monitoring
  const initDurationMs = performance.now() - initStart;
  console.log(`[PPO] Service Worker initialised in ${initDurationMs.toFixed(2)}ms`);
}

// ---------------------------------------------------------------------------
// handleNetworkStream — Task 10.1 + Task 10.2
// REQ 1.1, 1.2, 1.3, 11.1, 11.5, 12.1, 12.3, 12.4, 12.5
// ---------------------------------------------------------------------------

/**
 * Counter of in-flight requests currently being processed by the pipeline.
 * Exported for testing and for the GC manager (Task 10.2).
 *
 * REQ 12.1
 */
export let activeRequests: number = 0;

/**
 * Global telemetry stats — tracks cumulative activity since Service Worker start.
 */
export const _globalStats = {
  totalBytesProcessed: 0,
  totalTransitions: 0,
  meshUpdatesReceived: 0,
  startTime: Date.now(),
  lastDpiScore: 0,
};

// ---------------------------------------------------------------------------
// GC management (Task 10.2 — REQ 11.1, 11.5)
// ---------------------------------------------------------------------------

/**
 * Pending GC timeout ID. Non-null when a GC invocation is scheduled.
 * Exported for testing purposes.
 *
 * REQ 11.1
 */
export let _gcTimeoutId: ReturnType<typeof setTimeout> | null = null;

/**
 * Memory threshold in bytes below which degraded mode is deactivated (120 MB).
 * REQ 12.4
 */
const MEMORY_THRESHOLD_BYTES = 120 * 1024 * 1024;

/**
 * Degraded mode flag. When true, chunks are passed through without obfuscation
 * because the Go-Wasm engine has signalled MEMORY_LIMIT_EXCEEDED.
 *
 * Exported so tests and the GC recovery path can inspect / reset it.
 * REQ 11.5, 12.3
 */
export let degradedMode: boolean = false;

/**
 * Invokes the Go-Wasm GC function exported as `triggerGC` on `globalThis`.
 * Wrapped in try-catch so a missing export never crashes the pipeline.
 *
 * REQ 11.1
 */
export function triggerGC(): void {
  try {
    (globalThis as any).triggerGC?.();
  } catch (err) {
    console.warn('[PPO] triggerGC: error invoking Go-Wasm GC', err);
  }
}

/**
 * Checks current JS heap usage and exits degraded mode if memory has dropped
 * below the 120 MB threshold.
 *
 * Uses the Chrome-specific `performance.memory` API when available.
 * REQ 12.4
 */
function _checkMemoryAndRecover(): void {
  const mem = (performance as any).memory;
  if (mem && typeof mem.usedJSHeapSize === 'number') {
    if (mem.usedJSHeapSize < MEMORY_THRESHOLD_BYTES) {
      degradedMode = false;
      console.log('[PPO] Memory usage recovered — exiting degraded mode');
    }
  } else {
    // No memory API available — conservatively exit degraded mode so
    // obfuscation is not permanently disabled in non-Chrome environments.
    degradedMode = false;
  }
}

/** Latency threshold in milliseconds (REQ 12.5). */
const LATENCY_THRESHOLD_MS = 15;

/**
 * Intercepts a network stream (HTTP/HTTPS/WebSocket), obfuscates each chunk
 * through the Go-Wasm engine, and writes the result to the writable stream.
 *
 * Behaviour:
 *   1. If `url` matches the bypass list, pipe the stream directly without
 *      obfuscation (REQ 1.2, 1.3).
 *   2. If `degradedMode` is active (MEMORY_LIMIT_EXCEEDED was previously
 *      signalled), pipe the stream directly and attempt memory recovery
 *      (REQ 11.5, 12.3).
 *   3. Otherwise, for each chunk:
 *      a. Allocate a Wasm buffer, write the chunk, call processBytes with the
 *         current FSM state, read the result, free both buffers (REQ 1.1).
 *      b. If processBytes returns/throws MEMORY_LIMIT_EXCEEDED, activate
 *         degraded mode and send the original chunk (REQ 12.3).
 *      c. Measure processing latency. If > 15ms, send the chunk as-is and
 *         log a warning (REQ 12.5).
 *   4. `activeRequests` is incremented at the start and decremented in the
 *      finally block regardless of success or failure (REQ 12.1).
 *   5. Any pending GC timeout is cancelled when a new request arrives, and
 *      a new GC timeout is scheduled when activeRequests drops to 0 (REQ 11.1).
 *
 * @param readable  - Source stream of raw network bytes.
 * @param writable  - Destination stream for (possibly obfuscated) bytes.
 * @param url       - URL of the request, used for bypass evaluation.
 */
export async function handleNetworkStream(
  readable: ReadableStream<Uint8Array>,
  writable: WritableStream<Uint8Array>,
  url: string,
): Promise<void> {
  // REQ 11.1 — cancel any pending GC timeout when a new request arrives
  if (_gcTimeoutId !== null) {
    clearTimeout(_gcTimeoutId);
    _gcTimeoutId = null;
  }

  activeRequests++;

  const reader = readable.getReader();
  const writer = writable.getWriter();

  try {
    // REQ 1.2, 1.3 — bypass check: pipe directly if URL is in the bypass list
    if (getBypassManager().shouldBypass(url)) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value);
      }
      return;
    }

    // REQ 11.5, 12.3 — degraded mode: pipe directly without obfuscation
    if (degradedMode) {
      _checkMemoryAndRecover();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value);
      }
      return;
    }

    // Obfuscation path — requires the Wasm bridge and the active FSM state
    const bridge = await getWasmInstance();
    const fsm = getMarkovFSM();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      _globalStats.totalBytesProcessed += value.byteLength;

      const currentState: EvasionState = fsm.getCurrentState();
      const t0 = performance.now();

      let resultBytes: Uint8Array;
      try {
        // Allocate buffer, write chunk, process, read result, free buffers
        const ptr = bridge.allocateBuffer(value.byteLength);
        bridge.writeBuffer(ptr, value);
        const resultPtr = bridge.processBytes(ptr, value.byteLength, currentState);
        const resultBuf = bridge.readBuffer(resultPtr, value.byteLength);
        bridge.freeBuffer(ptr);
        bridge.freeBuffer(resultPtr);
        resultBytes = new Uint8Array(resultBuf);
      } catch (err: any) {
        // REQ 12.3 — if MEMORY_LIMIT_EXCEEDED, activate degraded mode and
        // pass the original chunk through
        const msg: string = err?.message ?? String(err);
        if (msg.includes('MEMORY_LIMIT_EXCEEDED')) {
          degradedMode = true;
          console.warn('[PPO] handleNetworkStream: MEMORY_LIMIT_EXCEEDED — activating degraded mode');
          await writer.write(value);
          continue;
        }
        // Record the failure as a DPI signal (Signal 1)
        getDpiDetector().recordRequest(url, 0, true, currentState);
        throw err;
      }

      const elapsed = performance.now() - t0;

      // REQ 12.5 — latency guard
      if (elapsed > LATENCY_THRESHOLD_MS) {
        console.warn(
          `[PPO] handleNetworkStream: processing latency ${elapsed.toFixed(2)}ms ` +
          `exceeds ${LATENCY_THRESHOLD_MS}ms threshold — sending chunk in current state`,
          { url, state: currentState, latencyMs: elapsed },
        );
        await writer.write(value);
      } else {
        // Apply new evasion components based on active state (REQ 8.2, 8.4, 8.5)
        if (currentState === 0x01 && _hostFragmenterEnabled) {
          // SPLIT state: apply HTTP Host Fragmentation (REQ 3.1, 8.4)
          // fragmentHttpHost already guards against TLS ClientHello (buf[0] === 0x16)
          const chunks = fragmentHttpHost(resultBytes);
          for (const chunk of chunks) {
            await writer.write(chunk);
          }
        } else if (currentState === 0x02 && _chunkRandomizerEnabled) {
          // DISORDER state: apply Chunk Size Randomization (REQ 4.1, 4.5)
          const chunks = getChunkRandomizer().randomize(resultBytes);
          for (const chunk of chunks) {
            await writer.write(chunk);
          }
        } else {
          await writer.write(resultBytes);
        }
      }

      // Record outcome in StrategyEvaluator if enabled (REQ 5.1)
      if (_strategyEvaluatorEnabled) {
        try {
          const baselineLatencyMs = 5; // conservative baseline
          getStrategyEvaluator().recordOutcome(currentState, elapsed, false, baselineLatencyMs);
        } catch {
          // Non-fatal — evaluator errors must not disrupt the pipeline
        }
      }

      // Record request outcome in the DPI detector (Signals 1, 2, 3, 4)
      getDpiDetector().recordRequest(url, elapsed, false, currentState);

      // REQ 8.3 — drive FSM transition using live DPI score
      const dpiScore = getDpiDetector().getScore();
      fsm.transition({
        latencyMs: elapsed,
        bandwidthBps: 0,
        packetLossRate: 0,
        dpiDetectionScore: dpiScore,
      });
      _globalStats.totalTransitions++;
      _globalStats.lastDpiScore = dpiScore;
    }
  } finally {
    // REQ 12.1 — always decrement, even on error
    activeRequests--;

    // REQ 11.1 — schedule GC when all requests have completed
    if (activeRequests === 0) {
      _gcTimeoutId = setTimeout(triggerGC, 100);
    }

    // Release stream locks so callers can close the streams
    try { reader.releaseLock(); } catch { /* ignore */ }
    try { writer.releaseLock(); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Auto-initialise when loaded as a Chrome Extension Service Worker
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// External Messaging API (REQ 12.6 - New)
// ---------------------------------------------------------------------------

/**
 * Handles incoming messages from the monitor UI or popup.
 *
 * Supported actions:
 *   - 'GET_PPO_STATUS': Returns current FSM state, request counts, memory metrics, and mesh info.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'GET_PPO_STATUS') {
    const fsm = getMarkovFSM();
    const mesh = getMeshNode();
    const mem = (performance as any).memory;
    const dpi = getDpiDetector().getSnapshot();

    sendResponse({
      fsm: {
        currentState: fsm.getCurrentState(),
        matrix: fsm.getTransitionProbabilities(),
      },
      pipeline: {
        activeRequests,
        degradedMode,
        wasmMode: _wasmInstance !== null
          ? (typeof (globalThis as any).ppoBridgeProcessBytes === 'function' ? 'wasm' : 'simulation')
          : 'simulation',
        memoryUsage: mem ? {
          used: mem.usedJSHeapSize,
          limit: mem.jsHeapSizeLimit,
        } : null,
      },
      mesh: {
        nodeId: mesh.nodeId,
        mode: mesh.getMode(),
        peerCount: mesh.getPeerCount(),
      },
      stats: {
        totalBytesProcessed: _globalStats.totalBytesProcessed,
        totalTransitions: _globalStats.totalTransitions,
        meshUpdatesReceived: _globalStats.meshUpdatesReceived,
        uptime: Math.floor((Date.now() - _globalStats.startTime) / 1000),
      },
      dpi: {
        score: dpi.score,
        level: dpi.level,
        dominantSignal: dpi.dominantSignal,
        signals: dpi.signals,
      },
      probe: (() => {
        const p = _censorshipProbe;
        if (!p) return undefined;
        const results = Array.from(p.getLatestResults().values()).map(r => ({
          url: r.url,
          ttfbMs: r.ttfbMs,
          connectionFailed: r.connectionFailed,
          timestamp: r.timestamp,
        }));
        return {
          intervalMs: (p as any).probeIntervalMs ?? 300_000,
          canaryCount: results.length || 5,
          lastCycleAt: p.getLastCycleTimestamp(),
          lastCycleFailures: p.getLastCycleFailureCount(),
          latestResults: results,
          canaryEntries: p.getCanaryEntries(),
          userCanaryUrls: p.getUserCanaryUrls(),
        };
      })(),
      evaluator: (() => {
        try {
          const e = getStrategyEvaluator();
          return e.getState();
        } catch {
          return undefined;
        }
      })(),
      chunkIntensity: (() => {
        try { return getChunkRandomizer().getIntensity(); } catch { return 'mild'; }
      })(),
      hostFragmentationActive: getMarkovFSM().getCurrentState() === 0x01 && _hostFragmenterEnabled,
      timestamp: Date.now(),
    });
  } else if (message.action === 'FORCE_TACTIC') {
    if (message.state) {
      getMarkovFSM().setManualState(message.state as EvasionState);
      manualOverrideActive = true;
      sendResponse({ success: true });
    }
  } else if (message.action === 'RESET_STRATEGY_EVALUATOR') {
    try {
      getStrategyEvaluator().reset();
      manualOverrideActive = false;
    } catch { /* evaluator not initialized */ }
    sendResponse({ success: true });

  } else if (message.action === 'TOGGLE_STRATEGY_EVALUATOR') {
    let active = false;
    try {
      active = getStrategyEvaluator().toggle();
    } catch { /* evaluator not initialized */ }
    sendResponse({ success: true, active });

  } else if (message.action === 'SET_USER_CANARY_URLS') {
    const urls: string[] = message.urls ?? [];
    const errors = getCensorshipProbe()?.setUserCanaryUrls(urls) ?? [];
    // Persist to chrome.storage.session
    if (typeof chrome !== 'undefined' && chrome.storage) {
      void chrome.storage.session.set({ ppo_canary_urls: urls });
    }
    sendResponse({ success: true, errors });

  } else if (message.action === 'GET_CANARY_ENTRIES') {
    const entries = getCensorshipProbe()?.getCanaryEntries() ?? [];
    sendResponse({ success: true, entries });

  } else if (message.action === 'SET_CHUNK_INTENSITY') {
    if (message.intensity === 'mild' || message.intensity === 'aggressive') {
      try {
        getChunkRandomizer().setIntensity(message.intensity);
        if (typeof chrome !== 'undefined' && chrome.storage) {
          void chrome.storage.session.set({ ppo_chunk_intensity: message.intensity });
        }
      } catch { /* randomizer not initialized */ }
      sendResponse({ success: true });
    }
  }
  return true; // Keep the message channel open for async response
});

// Only auto-run when the chrome global is present (i.e. inside the extension).
// This guard prevents side-effects during unit tests.
if (typeof chrome !== 'undefined' && chrome.runtime) {
  void initialize();
  // Decay the DPI score every 5 seconds when no new anomalies are observed
  setInterval(() => getDpiDetector().decay(), 5000);
}
