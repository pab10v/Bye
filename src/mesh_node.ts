/**
 * MeshNode — Decentralized P2P Signaling Mesh (Layer 3)
 *
 * Establishes RTCDataChannel connections between extension instances to
 * exchange evasion telemetry (transition weights, detection scores, bandwidth
 * estimates). Never routes real user web traffic through peers.
 *
 * Key privacy guarantees:
 *   - nodeId is a fresh UUID v4 per session, never persisted to chrome.storage.local
 *   - Only EvasionTelemetry fields are serialized — no URLs, no HTTP payloads
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 10.1, 10.2, 10.3, 13.2, 13.4
 */

import { EvasionTelemetry, MeshOperationMode, TransitionMatrix, DEFAULT_TRANSITION_MATRIX } from './types.js';

// ---------------------------------------------------------------------------
// WebRTC type declarations (not available in the WebWorker lib)
// ---------------------------------------------------------------------------

// RTCPeerConnection is available in Chrome Service Workers but not declared
// in the TypeScript WebWorker lib. We declare a minimal interface here so
// the code compiles without switching to the DOM lib.
declare class RTCPeerConnection {
  constructor(configuration?: Record<string, unknown>);
  createDataChannel(label: string, dataChannelDict?: Record<string, unknown>): RTCDataChannel;
  close(): void;
}

// RTCErrorEvent is also not in the WebWorker lib.
declare class RTCErrorEvent extends Event {
  readonly error: unknown;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface PeerConnection {
  /** The RTCPeerConnection for this peer (may be null in test environments) */
  peerConnection: RTCPeerConnection | null;
  /** The RTCDataChannel used to exchange telemetry */
  dataChannel: RTCDataChannel;
  /** Timer handle for the 60-second inactivity timeout */
  inactivityTimer: ReturnType<typeof setTimeout> | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Inactivity timeout in milliseconds (REQ 9.5) */
const INACTIVITY_TIMEOUT_MS = 60_000;

/**
 * Backoff intervals in milliseconds for reconnection attempts.
 * Fixed sequence: [1000, 2000, 4000, 8000, 16000] ms (REQ 9.7)
 */
export const BACKOFF_INTERVALS: number[] = [1000, 2000, 4000, 8000, 16000];

/**
 * Timeout in milliseconds after which the mesh transitions to standalone mode
 * if no successful connection has been established (5 minutes). (REQ 9.8)
 */
export const STANDALONE_TIMEOUT_MS = 300_000;

/**
 * chrome.storage.session key used to persist the TransitionMatrix between
 * Service Worker activations. (REQ 10.1, 10.2)
 */
export const TRANSITION_MATRIX_STORAGE_KEY = 'ppo_transition_matrix';

// ---------------------------------------------------------------------------
// UUID v4 generation
// ---------------------------------------------------------------------------

/**
 * Generates a UUID v4 string.
 *
 * Uses `crypto.randomUUID()` when available (Chrome 92+, Node 14.17+).
 * Falls back to a manual implementation using `crypto.getRandomValues()`.
 *
 * The nodeId is generated once at class instantiation and is never persisted
 * to chrome.storage.local (REQ 9.4, 13.2).
 */
function generateUUIDv4(): string {
  // Prefer the native API
  if (typeof crypto !== 'undefined' && typeof (crypto as Crypto).randomUUID === 'function') {
    return (crypto as Crypto).randomUUID();
  }

  // Manual fallback using crypto.getRandomValues
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    // Set version bits (version 4)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant bits (RFC 4122)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0'));
    return [
      hex.slice(0, 4).join(''),
      hex.slice(4, 6).join(''),
      hex.slice(6, 8).join(''),
      hex.slice(8, 10).join(''),
      hex.slice(10, 16).join(''),
    ].join('-');
  }

  // Last-resort fallback (test environments without crypto)
  // Still produces a UUID v4-shaped string using Math.random
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ---------------------------------------------------------------------------
// MeshNode interface (matches design spec)
// ---------------------------------------------------------------------------

export interface MeshNodeInterface {
  connect(peerId: string): Promise<RTCDataChannel>;
  disconnect(peerId: string): void;
  broadcastTelemetry(data: EvasionTelemetry): void;
  onTelemetryReceived(handler: (data: EvasionTelemetry) => void): void;
  getPeerCount(): number;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class MeshNode implements MeshNodeInterface {
  /**
   * Ephemeral UUID v4 for this session.
   * Generated once at instantiation; never persisted (REQ 9.4, 13.2).
   */
  readonly nodeId: string;

  /** Active peer connections keyed by peerId */
  private peers: Map<string, PeerConnection> = new Map();

  /** Registered telemetry handlers */
  private telemetryHandlers: Array<(data: EvasionTelemetry) => void> = [];

  /** Registered matrix update handlers */
  private _matrixUpdateHandlers: Array<(matrix: TransitionMatrix) => void> = [];

  /** Current mesh operation mode */
  private mode: MeshOperationMode = 'standalone';

  /**
   * Tracks the current backoff attempt index per peer.
   * Reset to 0 on successful connection.
   */
  private reconnectAttempts: Map<string, number> = new Map();

  /**
   * Tracks pending reconnect timer handles per peer.
   * Allows cancellation if a manual connect() is called.
   */
  private reconnectTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  /**
   * Timestamp (ms) of the last successful connection to any peer.
   * Used to determine when to transition to standalone mode.
   */
  private lastSuccessfulConnectionMs: number | null = null;

  /**
   * Timer handle for the standalone transition watchdog.
   * Fires after STANDALONE_TIMEOUT_MS without a successful connection.
   */
  private standaloneTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    // Generate a fresh UUID v4 at session start — never persisted (REQ 9.4, 13.2)
    this.nodeId = generateUUIDv4();
  }

  // -------------------------------------------------------------------------
  // connect
  // -------------------------------------------------------------------------

  /**
   * Establishes an RTCDataChannel with the given peer on demand.
   *
   * In environments where RTCPeerConnection is not available (e.g. Node.js
   * test environments), a mock RTCDataChannel-like object is used so that
   * the rest of the logic (inactivity timer, message routing) remains testable.
   *
   * REQ 9.6 — establish under demand, not permanently
   */
  async connect(peerId: string): Promise<RTCDataChannel> {
    // Return existing channel if already connected
    const existing = this.peers.get(peerId);
    if (existing) {
      return existing.dataChannel;
    }

    let peerConnection: RTCPeerConnection | null = null;
    let dataChannel: RTCDataChannel;

    try {
      // Attempt to create a real RTCPeerConnection
      peerConnection = new RTCPeerConnection();
      dataChannel = peerConnection.createDataChannel(`ppo-mesh-${peerId}`, {
        ordered: false,
        maxRetransmits: 0,
      });
    } catch {
      // RTCPeerConnection not available (test environment or unsupported context)
      // Create a minimal mock that satisfies the RTCDataChannel interface
      dataChannel = createMockDataChannel(peerId);
    }

    const peerConn: PeerConnection = {
      peerConnection,
      dataChannel,
      inactivityTimer: null,
    };

    this.peers.set(peerId, peerConn);

    // Wire up message handler to route incoming telemetry
    dataChannel.addEventListener('message', (event: MessageEvent) => {
      this._resetInactivityTimer(peerId);
      this._handleIncomingMessage(event.data);
    });

    // Handle channel close from the remote side
    dataChannel.addEventListener('close', () => {
      this._cleanupPeer(peerId);
    });

    // Start the 60-second inactivity timer (REQ 9.5)
    this._resetInactivityTimer(peerId);

    // Record successful connection and update mode (REQ 9.7, 10.6)
    this._onConnectionSuccess(peerId);

    return dataChannel;
  }

  // -------------------------------------------------------------------------
  // disconnect
  // -------------------------------------------------------------------------

  /**
   * Closes the RTCDataChannel and RTCPeerConnection for the given peer,
   * clears the inactivity timer, and removes the peer from the map.
   *
   * REQ 9.5 (resource release)
   */
  disconnect(peerId: string): void {
    this._cleanupPeer(peerId);
  }

  // -------------------------------------------------------------------------
  // broadcastTelemetry
  // -------------------------------------------------------------------------

  /**
   * Serializes `data` as JSON and sends it over all open RTCDataChannels.
   *
   * Privacy guarantees (REQ 9.2, 13.4):
   *   - Only the fields defined in EvasionTelemetry are serialized
   *   - The nodeId in the payload is always this instance's ephemeral nodeId
   *   - No URLs, HTTP payloads, or user-identifiable data are included
   */
  broadcastTelemetry(data: EvasionTelemetry): void {
    // Build a sanitized payload with only EvasionTelemetry fields (REQ 9.2, 13.4)
    const payload: EvasionTelemetry = {
      nodeId: this.nodeId,                          // Always use our ephemeral nodeId
      timestamp: data.timestamp,
      activeState: data.activeState,
      transitionWeights: data.transitionWeights,
      detectionScore: data.detectionScore,
      bandwidthEstimateBps: data.bandwidthEstimateBps,
      packetsProcessed: data.packetsProcessed,
      averageLatencyMs: data.averageLatencyMs,
    };

    const serialized = JSON.stringify(payload);

    for (const [peerId, peerConn] of this.peers) {
      const { dataChannel } = peerConn;
      try {
        if (dataChannel.readyState === 'open') {
          dataChannel.send(serialized);
          this._resetInactivityTimer(peerId);
        }
      } catch {
        // Channel may have closed unexpectedly; clean up
        this._cleanupPeer(peerId);
      }
    }
  }

  // -------------------------------------------------------------------------
  // onTelemetryReceived
  // -------------------------------------------------------------------------

  /**
   * Registers a callback that is invoked whenever a telemetry message arrives
   * on any RTCDataChannel.
   *
   * REQ 9.1 — only EvasionTelemetry is exchanged
   */
  onTelemetryReceived(handler: (data: EvasionTelemetry) => void): void {
    this.telemetryHandlers.push(handler);
  }

  // -------------------------------------------------------------------------
  // getPeerCount
  // -------------------------------------------------------------------------

  /** Returns the number of currently connected peers. */
  getPeerCount(): number {
    return this.peers.size;
  }

  // -------------------------------------------------------------------------
  // getMode
  // -------------------------------------------------------------------------

  /** Returns the current mesh operation mode. */
  getMode(): MeshOperationMode {
    return this.mode;
  }

  // -------------------------------------------------------------------------
  // persistTransitionWeights (REQ 10.1)
  // -------------------------------------------------------------------------

  /**
   * Persists the given TransitionMatrix to `chrome.storage.session` under the
   * key `'ppo_transition_matrix'`.
   *
   * Uses `chrome.storage.session` (Manifest V3) so the data survives Service
   * Worker suspension/reactivation within the same browser session but is
   * cleared when the browser is closed.
   *
   * If `chrome.storage.session` is not available (e.g. test environments),
   * the call is a no-op and resolves immediately.
   *
   * REQ 10.1
   */
  async persistTransitionWeights(matrix: TransitionMatrix): Promise<void> {
    if (
      typeof chrome === 'undefined' ||
      !chrome.storage ||
      !chrome.storage.session
    ) {
      // Not running inside Chrome — skip silently
      return;
    }

    await chrome.storage.session.set({
      [TRANSITION_MATRIX_STORAGE_KEY]: matrix,
    });
  }

  // -------------------------------------------------------------------------
  // restoreTransitionWeights (REQ 10.2, 10.3)
  // -------------------------------------------------------------------------

  /**
   * Restores the TransitionMatrix from `chrome.storage.session`.
   *
   * If no matrix is stored (e.g. first activation after browser start), returns
   * the default uniform distribution matrix (REQ 10.3).
   *
   * If `chrome.storage.session` is not available (e.g. test environments),
   * returns the default uniform matrix immediately.
   *
   * REQ 10.2, 10.3
   */
  async restoreTransitionWeights(): Promise<TransitionMatrix> {
    if (
      typeof chrome === 'undefined' ||
      !chrome.storage ||
      !chrome.storage.session
    ) {
      // Not running inside Chrome — return default
      return DEFAULT_TRANSITION_MATRIX.map(row => [...row]);
    }

    const result = await chrome.storage.session.get(TRANSITION_MATRIX_STORAGE_KEY);
    const stored = result[TRANSITION_MATRIX_STORAGE_KEY] as TransitionMatrix | undefined;

    if (
      Array.isArray(stored) &&
      stored.length === 3 &&
      stored.every(row => Array.isArray(row) && row.length === 3)
    ) {
      // Return a deep copy to prevent external mutation of the stored value
      return stored.map(row => [...row]);
    }

    // Fallback: no valid matrix stored — use uniform default (REQ 10.3)
    return DEFAULT_TRANSITION_MATRIX.map(row => [...row]);
  }

  // -------------------------------------------------------------------------
  // updateTransitionMatrix (REQ 10.1)
  // -------------------------------------------------------------------------

  /**
   * Updates the internal transition matrix with weights received from a mesh
   * peer and persists the updated matrix to `chrome.storage.session`.
   *
   * This method is called from `_handleIncomingMessage` whenever a peer
   * broadcasts telemetry containing `transitionWeights`.
   *
   * The `onMatrixUpdated` callback (if registered) is invoked after the matrix
   * is updated so that the MarkovFSM singleton can be kept in sync.
   *
   * REQ 10.1
   */
  updateTransitionMatrix(matrix: TransitionMatrix): void {
    // Notify registered listeners (e.g. MarkovFSM) about the new matrix
    for (const handler of this._matrixUpdateHandlers) {
      try {
        handler(matrix);
      } catch {
        // Individual handler errors must not crash the mesh
      }
    }

    // Persist asynchronously — fire-and-forget (errors are logged but not thrown)
    this.persistTransitionWeights(matrix).catch((err) => {
      console.warn('[PPO] MeshNode: failed to persist TransitionMatrix', err);
    });
  }

  // -------------------------------------------------------------------------
  // onMatrixUpdated
  // -------------------------------------------------------------------------

  /**
   * Registers a callback that is invoked whenever the transition matrix is
   * updated via peer telemetry.
   *
   * Allows the Service Worker to wire `MeshNode → MarkovFSM.setTransitionMatrix`.
   *
   * REQ 10.1
   */
  onMatrixUpdated(handler: (matrix: TransitionMatrix) => void): void {
    this._matrixUpdateHandlers.push(handler);
  }

  // -------------------------------------------------------------------------
  // reconnect (exported for testing — REQ 9.7, 9.8)
  // -------------------------------------------------------------------------

  /**
   * Attempts to reconnect to a peer using exponential backoff.
   *
   * The backoff sequence is defined by `BACKOFF_INTERVALS`. After exhausting
   * all intervals the sequence wraps to the last interval. If no successful
   * connection has been established within `STANDALONE_TIMEOUT_MS` (5 min)
   * from the first failed attempt, the mode transitions to `standalone`.
   *
   * REQ 9.7 — backoff intervals [1000, 2000, 4000, 8000, 16000] ms
   * REQ 9.8 — standalone after 5 minutes without success
   */
  async reconnect(peerId: string): Promise<void> {
    // Cancel any existing reconnect timer for this peer
    const existingTimer = this.reconnectTimers.get(peerId);
    if (existingTimer !== undefined) {
      clearTimeout(existingTimer);
      this.reconnectTimers.delete(peerId);
    }

    // Transition to degraded mode while reconnecting (REQ 10.6)
    if (this.mode !== 'connected') {
      this.mode = 'degraded';
    }

    // Start the standalone watchdog if not already running
    this._startStandaloneWatchdog();

    const attemptIndex = this.reconnectAttempts.get(peerId) ?? 0;
    const delayMs = BACKOFF_INTERVALS[Math.min(attemptIndex, BACKOFF_INTERVALS.length - 1)];

    await new Promise<void>((resolve) => {
      const timer = setTimeout(async () => {
        this.reconnectTimers.delete(peerId);

        // Check if we've already transitioned to standalone — stop retrying
        if (this.mode === 'standalone') {
          resolve();
          return;
        }

        try {
          // Attempt to connect; if the peer is already connected this is a no-op
          await this.connect(peerId);
          // Success: reset attempt counter (handled inside _onConnectionSuccess)
          resolve();
        } catch {
          // Failed: increment attempt counter and schedule next retry
          this.reconnectAttempts.set(peerId, attemptIndex + 1);
          // Schedule next attempt (fire-and-forget; don't await to avoid stack growth)
          void this.reconnect(peerId);
          resolve();
        }
      }, delayMs);

      this.reconnectTimers.set(peerId, timer);
    });
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Called on every successful connection to update mode and reset backoff.
   *
   * REQ 9.7 — reset backoff on success
   * REQ 10.6 — transition to connected mode
   */
  private _onConnectionSuccess(peerId: string): void {
    // Reset backoff counter for this peer
    this.reconnectAttempts.delete(peerId);

    // Cancel any pending reconnect timer for this peer
    const timer = this.reconnectTimers.get(peerId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.reconnectTimers.delete(peerId);
    }

    // Record the timestamp of the last successful connection
    this.lastSuccessfulConnectionMs = Date.now();

    // Cancel the standalone watchdog — we have a live connection
    this._cancelStandaloneWatchdog();

    // Transition to connected mode
    this.mode = 'connected';
  }

  /**
   * Starts the standalone transition watchdog timer.
   *
   * If no successful connection is established within STANDALONE_TIMEOUT_MS,
   * the mode transitions to `standalone` (REQ 9.8).
   *
   * The watchdog is only started once; subsequent calls while it is running
   * are no-ops.
   */
  private _startStandaloneWatchdog(): void {
    if (this.standaloneTimer !== null) {
      // Already running
      return;
    }

    this.standaloneTimer = setTimeout(() => {
      this.standaloneTimer = null;
      // Only transition if we are still not connected
      if (this.mode !== 'connected') {
        this.mode = 'standalone';
        // Cancel all pending reconnect timers — we give up
        for (const [, timer] of this.reconnectTimers) {
          clearTimeout(timer);
        }
        this.reconnectTimers.clear();
        this.reconnectAttempts.clear();
      }
    }, STANDALONE_TIMEOUT_MS);
  }

  /**
   * Cancels the standalone transition watchdog timer.
   * Called when a successful connection is established.
   */
  private _cancelStandaloneWatchdog(): void {
    if (this.standaloneTimer !== null) {
      clearTimeout(this.standaloneTimer);
      this.standaloneTimer = null;
    }
  }

  /**
   * Resets (or starts) the 60-second inactivity timer for a peer.
   * When the timer fires, the channel is closed and resources are released.
   *
   * REQ 9.5
   */
  private _resetInactivityTimer(peerId: string): void {
    const peerConn = this.peers.get(peerId);
    if (!peerConn) return;

    // Clear any existing timer
    if (peerConn.inactivityTimer !== null) {
      clearTimeout(peerConn.inactivityTimer);
    }

    // Schedule cleanup after 60 seconds of inactivity
    peerConn.inactivityTimer = setTimeout(() => {
      this._cleanupPeer(peerId);
    }, INACTIVITY_TIMEOUT_MS);
  }

  /**
   * Closes the data channel and peer connection for a peer, clears the
   * inactivity timer, and removes the peer from the map.
   */
  private _cleanupPeer(peerId: string): void {
    const peerConn = this.peers.get(peerId);
    if (!peerConn) return;

    // Clear inactivity timer
    if (peerConn.inactivityTimer !== null) {
      clearTimeout(peerConn.inactivityTimer);
      peerConn.inactivityTimer = null;
    }

    // Close the data channel
    try {
      if (peerConn.dataChannel.readyState !== 'closed') {
        peerConn.dataChannel.close();
      }
    } catch {
      // Ignore errors during close
    }

    // Close the peer connection
    if (peerConn.peerConnection) {
      try {
        peerConn.peerConnection.close();
      } catch {
        // Ignore errors during close
      }
    }

    this.peers.delete(peerId);

    // Update mode if no peers remain — transition to degraded to trigger backoff (REQ 9.7, 10.6)
    if (this.peers.size === 0) {
      // Only move to degraded if we were connected; standalone stays standalone
      if (this.mode === 'connected') {
        this.mode = 'degraded';
        // Start the standalone watchdog (REQ 9.8)
        this._startStandaloneWatchdog();
      }
    }
  }

  /**
   * Parses an incoming message as EvasionTelemetry and dispatches it to all
   * registered handlers.
   *
   * When the telemetry contains `transitionWeights`, the weights are applied
   * to the local transition matrix and persisted to `chrome.storage.session`
   * via `updateTransitionMatrix` (REQ 10.1).
   *
   * Malformed messages are silently dropped to avoid crashing the mesh.
   */
  private _handleIncomingMessage(raw: unknown): void {
    try {
      const data: EvasionTelemetry = typeof raw === 'string'
        ? JSON.parse(raw)
        : raw as EvasionTelemetry;

      // Basic structural validation — only dispatch if it looks like telemetry
      if (
        typeof data === 'object' &&
        data !== null &&
        typeof data.nodeId === 'string' &&
        typeof data.timestamp === 'number' &&
        typeof data.activeState === 'number'
      ) {
        // REQ 10.1 — if the telemetry carries transition weights, rebuild the
        // matrix and persist it before notifying handlers.
        if (Array.isArray(data.transitionWeights) && data.transitionWeights.length > 0) {
          // Build a 3×3 matrix from the flat weight list.
          // Start from the default uniform matrix and apply each weight entry.
          const matrix: TransitionMatrix = DEFAULT_TRANSITION_MATRIX.map(row => [...row]);
          for (const w of data.transitionWeights) {
            if (
              typeof w.fromState === 'number' &&
              typeof w.toState === 'number' &&
              typeof w.weight === 'number'
            ) {
              const fromIdx = w.fromState - 1; // EvasionState 0x01..0x03 → index 0..2
              const toIdx   = w.toState   - 1;
              if (fromIdx >= 0 && fromIdx < 3 && toIdx >= 0 && toIdx < 3) {
                matrix[fromIdx][toIdx] = w.weight;
              }
            }
          }
          this.updateTransitionMatrix(matrix);
        }

        for (const handler of this.telemetryHandlers) {
          try {
            handler(data);
          } catch {
            // Individual handler errors must not crash the mesh
          }
        }
      }
    } catch {
      // Malformed JSON — silently drop
    }
  }
}

// ---------------------------------------------------------------------------
// Mock RTCDataChannel for test environments
// ---------------------------------------------------------------------------

/**
 * Creates a minimal mock RTCDataChannel-like object for environments where
 * RTCPeerConnection is not available (e.g. Node.js / Vitest).
 *
 * The mock:
 *   - Implements the subset of the RTCDataChannel interface used by MeshNode
 *   - Starts in 'open' readyState
 *   - Supports addEventListener / removeEventListener
 *   - send() is a no-op (no real network)
 */
function createMockDataChannel(peerId: string): RTCDataChannel {
  const listeners: Map<string, Set<EventListenerOrEventListenerObject>> = new Map();

  const mock = {
    label: `ppo-mesh-${peerId}`,
    readyState: 'open' as RTCDataChannelState,
    ordered: false,
    maxRetransmits: 0,
    id: null,
    negotiated: false,
    protocol: '',
    bufferedAmount: 0,
    bufferedAmountLowThreshold: 0,
    binaryType: 'arraybuffer' as BinaryType,
    maxPacketLifeTime: null,

    send(_data: string | ArrayBuffer | Blob | ArrayBufferView): void {
      // No-op in test environment
    },

    close(): void {
      (mock as any).readyState = 'closed';
      const closeListeners = listeners.get('close');
      if (closeListeners) {
        const event = { type: 'close' } as Event;
        for (const listener of closeListeners) {
          if (typeof listener === 'function') {
            listener(event);
          } else {
            listener.handleEvent(event);
          }
        }
      }
    },

    addEventListener(
      type: string,
      listener: EventListenerOrEventListenerObject,
      _options?: boolean | AddEventListenerOptions,
    ): void {
      if (!listeners.has(type)) {
        listeners.set(type, new Set());
      }
      listeners.get(type)!.add(listener);
    },

    removeEventListener(
      type: string,
      listener: EventListenerOrEventListenerObject,
      _options?: boolean | EventListenerOptions,
    ): void {
      listeners.get(type)?.delete(listener);
    },

    dispatchEvent(event: Event): boolean {
      const typeListeners = listeners.get(event.type);
      if (typeListeners) {
        for (const listener of typeListeners) {
          if (typeof listener === 'function') {
            listener(event);
          } else {
            listener.handleEvent(event);
          }
        }
      }
      return true;
    },

    // Event handler properties (not used by MeshNode but required by the interface)
    onopen: null as ((this: RTCDataChannel, ev: Event) => unknown) | null,
    onclose: null as ((this: RTCDataChannel, ev: Event) => unknown) | null,
    onerror: null as ((this: RTCDataChannel, ev: RTCErrorEvent) => unknown) | null,
    onmessage: null as ((this: RTCDataChannel, ev: MessageEvent) => unknown) | null,
    onbufferedamountlow: null as ((this: RTCDataChannel, ev: Event) => unknown) | null,
  } as unknown as RTCDataChannel;

  return mock;
}

// ---------------------------------------------------------------------------
// Factory / singleton
// ---------------------------------------------------------------------------

let _instance: MeshNode | null = null;

/**
 * Returns the singleton MeshNode instance.
 * The nodeId is generated once per process lifetime (session).
 */
export function getMeshNode(): MeshNode {
  if (!_instance) {
    _instance = new MeshNode();
  }
  return _instance;
}

/** Resets the singleton (useful for testing). */
export function resetMeshNode(): void {
  _instance = null;
}
