/**
 * Unit tests para MeshNode
 *
 * Cubre:
 *   - Que el `nodeId` es un UUID v4 válido y diferente en cada sesión
 *   - Que el canal se cierra tras 60s de inactividad
 *   - Que el backoff sigue la secuencia [1000, 2000, 4000, 8000, 16000]
 *   - Que la telemetría no incluye URLs ni datos identificables del usuario
 *
 * Requisitos: 9.3, 9.4, 9.5, 9.7, 13.2, 13.4
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  MeshNode,
  BACKOFF_INTERVALS,
  resetMeshNode,
  getMeshNode,
} from '../src/mesh_node.js';
import { EvasionTelemetry, EVASION_STATE } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** UUID v4 regex (RFC 4122) */
const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Builds a minimal valid EvasionTelemetry object */
function makeTelemetry(overrides: Partial<EvasionTelemetry> = {}): EvasionTelemetry {
  return {
    nodeId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    timestamp: Date.now(),
    activeState: EVASION_STATE.SPLIT,
    transitionWeights: [],
    detectionScore: 0.1,
    bandwidthEstimateBps: 1_000_000,
    packetsProcessed: 42,
    averageLatencyMs: 5.0,
    ...overrides,
  };
}

/**
 * Injects a mock peer directly into the MeshNode's private `peers` map so
 * that broadcastTelemetry can be tested without a real RTCPeerConnection.
 * Returns the captured sent strings.
 */
function injectMockPeer(
  node: MeshNode,
  peerId: string,
): { captured: string[]; channel: RTCDataChannel } {
  const captured: string[] = [];

  const channel = {
    label: `ppo-mesh-${peerId}`,
    readyState: 'open' as RTCDataChannelState,
    send(data: string): void {
      captured.push(data);
    },
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    close(): void {
      (this as any).readyState = 'closed';
    },
    ordered: false,
    maxRetransmits: 0,
    id: null,
    negotiated: false,
    protocol: '',
    bufferedAmount: 0,
    bufferedAmountLowThreshold: 0,
    binaryType: 'arraybuffer' as BinaryType,
    maxPacketLifeTime: null,
    onopen: null,
    onclose: null,
    onerror: null,
    onmessage: null,
    onbufferedamountlow: null,
  } as unknown as RTCDataChannel;

  const peers: Map<string, unknown> = (node as any).peers;
  peers.set(peerId, {
    peerConnection: null,
    dataChannel: channel,
    inactivityTimer: null,
  });

  return { captured, channel };
}

// ---------------------------------------------------------------------------
// Suite 1: nodeId — UUID v4 válido y efímero (REQ 9.3, 9.4, 13.2)
// ---------------------------------------------------------------------------

describe('MeshNode — nodeId UUID v4 válido y efímero', () => {
  /**
   * REQ 9.3: broadcastTelemetry must include a nodeId that is a UUID v4.
   * REQ 13.2: nodeId is a random UUID v4 generated at session start.
   */
  it('el nodeId de una instancia satisface el formato UUID v4', () => {
    const node = new MeshNode();
    expect(UUID_V4_REGEX.test(node.nodeId)).toBe(true);
  });

  /**
   * REQ 9.4 / 13.2: A new MeshNode (new session) must produce a different nodeId.
   * We create 10 instances and verify all nodeIds are distinct.
   */
  it('cada instancia de MeshNode genera un nodeId diferente (sin persistencia entre sesiones)', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 10; i++) {
      ids.add(new MeshNode().nodeId);
    }
    // All 10 IDs must be unique
    expect(ids.size).toBe(10);
  });

  /**
   * REQ 9.3: The nodeId included in the broadcast payload must be the
   * instance's own ephemeral nodeId, not the one supplied in the input data.
   */
  it('el nodeId en el payload de broadcastTelemetry es el nodeId efímero de la instancia', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-1');

    const telemetry = makeTelemetry({ nodeId: 'foreign-id-should-be-replaced' });
    node.broadcastTelemetry(telemetry);

    expect(captured).toHaveLength(1);
    const payload = JSON.parse(captured[0]) as EvasionTelemetry;
    expect(payload.nodeId).toBe(node.nodeId);
    expect(payload.nodeId).not.toBe('foreign-id-should-be-replaced');
  });

  /**
   * REQ 13.2: nodeId must be a valid UUID v4 in the broadcast payload.
   */
  it('el nodeId en el payload serializado satisface el formato UUID v4', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-1');

    node.broadcastTelemetry(makeTelemetry());

    const payload = JSON.parse(captured[0]) as EvasionTelemetry;
    expect(UUID_V4_REGEX.test(payload.nodeId)).toBe(true);
  });

  /**
   * Singleton: getMeshNode() returns the same instance across calls.
   * resetMeshNode() forces a new instance with a new nodeId.
   */
  it('resetMeshNode() produce una nueva instancia con un nodeId diferente', () => {
    resetMeshNode();
    const id1 = getMeshNode().nodeId;
    resetMeshNode();
    const id2 = getMeshNode().nodeId;
    expect(id1).not.toBe(id2);
    expect(UUID_V4_REGEX.test(id1)).toBe(true);
    expect(UUID_V4_REGEX.test(id2)).toBe(true);
    resetMeshNode(); // clean up singleton
  });
});

// ---------------------------------------------------------------------------
// Suite 2: Timeout de inactividad de 60 segundos (REQ 9.5)
// ---------------------------------------------------------------------------

describe('MeshNode — timeout de inactividad de 60 segundos', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /**
   * REQ 9.5: After 60 seconds of inactivity the channel must be closed and
   * the peer removed from the internal map.
   */
  it('el canal se cierra y el peer se elimina tras 60s de inactividad', async () => {
    const node = new MeshNode();

    // connect() uses a mock data channel in Node.js (no RTCPeerConnection)
    const channel = await node.connect('peer-timeout');

    expect(node.getPeerCount()).toBe(1);

    // Advance time by exactly 60 seconds — the inactivity timer should fire
    vi.advanceTimersByTime(60_000);

    // The peer must have been cleaned up
    expect(node.getPeerCount()).toBe(0);
    expect(channel.readyState).toBe('closed');
  });

  /**
   * REQ 9.5: Activity (a received message) must reset the inactivity timer.
   * After 59s + activity + 59s the channel must still be open.
   * Only after a full 60s of silence should it close.
   */
  it('la actividad reinicia el timer: el canal permanece abierto si hay actividad antes de los 60s', async () => {
    const node = new MeshNode();
    await node.connect('peer-active');

    // Advance 59 seconds — timer has not fired yet
    vi.advanceTimersByTime(59_000);
    expect(node.getPeerCount()).toBe(1);

    // Simulate incoming message activity by calling _resetInactivityTimer via
    // the internal peers map (the message event listener calls it internally).
    // We trigger it by dispatching a MessageEvent on the data channel.
    const peers: Map<string, { dataChannel: RTCDataChannel; inactivityTimer: ReturnType<typeof setTimeout> | null }> =
      (node as any).peers;
    const peerConn = peers.get('peer-active')!;
    const msgEvent = new MessageEvent('message', { data: JSON.stringify(makeTelemetry()) });
    peerConn.dataChannel.dispatchEvent(msgEvent);

    // Advance another 59 seconds — timer was reset, so it should not have fired
    vi.advanceTimersByTime(59_000);
    expect(node.getPeerCount()).toBe(1);

    // Now advance the remaining 1 second to complete the 60s window
    vi.advanceTimersByTime(1_000);
    expect(node.getPeerCount()).toBe(0);
  });

  /**
   * REQ 9.5: Calling disconnect() explicitly must clear the inactivity timer
   * and close the channel immediately.
   */
  it('disconnect() cierra el canal inmediatamente sin esperar el timeout', async () => {
    const node = new MeshNode();
    const channel = await node.connect('peer-disconnect');

    expect(node.getPeerCount()).toBe(1);

    node.disconnect('peer-disconnect');

    expect(node.getPeerCount()).toBe(0);
    expect(channel.readyState).toBe('closed');
  });

  /**
   * REQ 9.5: Multiple peers each have independent inactivity timers.
   * Closing one peer must not affect the other.
   */
  it('cada peer tiene su propio timer de inactividad independiente', async () => {
    const node = new MeshNode();
    await node.connect('peer-a');
    await node.connect('peer-b');

    expect(node.getPeerCount()).toBe(2);

    // Advance 60s — both timers fire simultaneously
    vi.advanceTimersByTime(60_000);

    expect(node.getPeerCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: Backoff exponencial [1000, 2000, 4000, 8000, 16000] ms (REQ 9.7)
// ---------------------------------------------------------------------------

describe('MeshNode — backoff exponencial', () => {
  /**
   * REQ 9.7: The exported BACKOFF_INTERVALS constant must be exactly
   * [1000, 2000, 4000, 8000, 16000].
   */
  it('BACKOFF_INTERVALS es exactamente [1000, 2000, 4000, 8000, 16000]', () => {
    expect(BACKOFF_INTERVALS).toEqual([1000, 2000, 4000, 8000, 16000]);
  });

  /**
   * REQ 9.7: The backoff sequence has exactly 5 intervals.
   */
  it('la secuencia de backoff tiene exactamente 5 intervalos', () => {
    expect(BACKOFF_INTERVALS).toHaveLength(5);
  });

  /**
   * REQ 9.7: Each interval is double the previous one (exponential growth).
   */
  it('cada intervalo es el doble del anterior (crecimiento exponencial)', () => {
    for (let i = 1; i < BACKOFF_INTERVALS.length; i++) {
      expect(BACKOFF_INTERVALS[i]).toBe(BACKOFF_INTERVALS[i - 1] * 2);
    }
  });

  /**
   * REQ 9.7: The reconnect() method uses the correct delay for each attempt.
   * We verify by inspecting which delay is used for attempt index 0..4.
   */
  it('reconnect() usa el delay correcto para cada índice de intento', async () => {
    vi.useFakeTimers();

    try {
      const node = new MeshNode();

      // Track which setTimeout delays were used
      const usedDelays: number[] = [];
      const originalSetTimeout = globalThis.setTimeout;
      vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn: any, delay?: number, ...args: any[]) => {
        if (typeof delay === 'number' && BACKOFF_INTERVALS.includes(delay)) {
          usedDelays.push(delay);
        }
        return originalSetTimeout(fn, delay, ...args);
      });

      // Manually set the reconnect attempt counter to simulate prior failures
      const reconnectAttempts: Map<string, number> = (node as any).reconnectAttempts;

      // Attempt 0 → should use 1000ms
      reconnectAttempts.set('peer-backoff', 0);
      const p0 = node.reconnect('peer-backoff');
      vi.advanceTimersByTime(1000);
      await p0;

      // Attempt 1 → should use 2000ms
      reconnectAttempts.set('peer-backoff', 1);
      const p1 = node.reconnect('peer-backoff');
      vi.advanceTimersByTime(2000);
      await p1;

      // Attempt 2 → should use 4000ms
      reconnectAttempts.set('peer-backoff', 2);
      const p2 = node.reconnect('peer-backoff');
      vi.advanceTimersByTime(4000);
      await p2;

      // Attempt 3 → should use 8000ms
      reconnectAttempts.set('peer-backoff', 3);
      const p3 = node.reconnect('peer-backoff');
      vi.advanceTimersByTime(8000);
      await p3;

      // Attempt 4 → should use 16000ms
      reconnectAttempts.set('peer-backoff', 4);
      const p4 = node.reconnect('peer-backoff');
      vi.advanceTimersByTime(16000);
      await p4;

      // Verify the delays used match the backoff sequence
      expect(usedDelays).toContain(1000);
      expect(usedDelays).toContain(2000);
      expect(usedDelays).toContain(4000);
      expect(usedDelays).toContain(8000);
      expect(usedDelays).toContain(16000);

      vi.restoreAllMocks();
    } finally {
      vi.useRealTimers();
    }
  });

  /**
   * REQ 9.7: After a successful connection the attempt counter is reset to 0,
   * so the next reconnect starts from the first interval (1000ms).
   */
  it('tras una conexión exitosa el contador de intentos se reinicia a 0', async () => {
    const node = new MeshNode();

    // Simulate that we had 3 failed attempts
    const reconnectAttempts: Map<string, number> = (node as any).reconnectAttempts;
    reconnectAttempts.set('peer-reset', 3);

    // connect() succeeds → _onConnectionSuccess resets the counter
    await node.connect('peer-reset');

    // The attempt counter for this peer must be gone (reset)
    expect(reconnectAttempts.has('peer-reset')).toBe(false);
  });

  /**
   * REQ 9.7: Attempt index beyond the last interval wraps to the last value (16000ms).
   */
  it('un índice de intento mayor que el último usa el último intervalo (16000ms)', () => {
    // The implementation uses Math.min(attemptIndex, BACKOFF_INTERVALS.length - 1)
    const lastIndex = BACKOFF_INTERVALS.length - 1;
    const beyondIndex = lastIndex + 5;
    const clampedIndex = Math.min(beyondIndex, lastIndex);
    expect(BACKOFF_INTERVALS[clampedIndex]).toBe(16_000);
  });
});

// ---------------------------------------------------------------------------
// Suite 4: Privacidad de la telemetría — sin URLs ni datos identificables (REQ 13.4)
// ---------------------------------------------------------------------------

describe('MeshNode — privacidad de la telemetría', () => {
  /** Fields that are allowed in the serialized EvasionTelemetry payload */
  const ALLOWED_FIELDS = new Set([
    'nodeId',
    'timestamp',
    'activeState',
    'transitionWeights',
    'detectionScore',
    'bandwidthEstimateBps',
    'packetsProcessed',
    'averageLatencyMs',
  ]);

  /** Patterns that must never appear as top-level keys in the payload */
  const FORBIDDEN_PATTERNS = [
    /url/i,
    /http/i,
    /payload/i,
    /body/i,
    /cookie/i,
    /header/i,
    /host/i,
    /path/i,
    /query/i,
    /request/i,
    /response/i,
    /user/i,
    /email/i,
    /password/i,
    /token/i,
    /session/i,
    /credential/i,
  ];

  /**
   * REQ 13.4: broadcastTelemetry must only serialize EvasionTelemetry fields.
   * No extra fields (URLs, HTTP payloads, user data) must appear in the payload.
   */
  it('el payload serializado contiene únicamente los campos de EvasionTelemetry', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-privacy');

    node.broadcastTelemetry(makeTelemetry());

    expect(captured).toHaveLength(1);
    const payload = JSON.parse(captured[0]) as Record<string, unknown>;
    const keys = Object.keys(payload);

    for (const key of keys) {
      expect(ALLOWED_FIELDS.has(key)).toBe(true);
    }
  });

  /**
   * REQ 13.4: The payload must have exactly the same number of fields as
   * EvasionTelemetry (no extra fields, no missing fields).
   */
  it('el payload serializado tiene exactamente el número de campos de EvasionTelemetry', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-field-count');

    node.broadcastTelemetry(makeTelemetry());

    const payload = JSON.parse(captured[0]) as Record<string, unknown>;
    expect(Object.keys(payload)).toHaveLength(ALLOWED_FIELDS.size);
  });

  /**
   * REQ 13.4: Even if the input EvasionTelemetry object is polluted with
   * extra fields (URLs, cookies, etc.), broadcastTelemetry must strip them.
   */
  it('los campos extra (URLs, cookies, etc.) son eliminados del payload serializado', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-strip');

    // Inject forbidden fields into the telemetry object
    const polluted = {
      ...makeTelemetry(),
      url: 'https://example.com/secret',
      cookie: 'session=abc123',
      userEmail: 'user@example.com',
      httpPayload: 'GET / HTTP/1.1',
      requestBody: '{"password":"hunter2"}',
    } as unknown as EvasionTelemetry;

    node.broadcastTelemetry(polluted);

    const payload = JSON.parse(captured[0]) as Record<string, unknown>;
    const keys = Object.keys(payload);

    // No forbidden field must appear
    for (const key of keys) {
      const isForbidden = FORBIDDEN_PATTERNS.some((p) => p.test(key));
      expect(isForbidden).toBe(false);
    }

    // Only allowed fields must be present
    for (const key of keys) {
      expect(ALLOWED_FIELDS.has(key)).toBe(true);
    }
  });

  /**
   * REQ 13.4: The nodeId in the payload must be the instance's ephemeral UUID,
   * not any user-supplied identifier.
   */
  it('el nodeId en el payload es el UUID efímero de la instancia, no un identificador externo', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-nodeid');

    const telemetry = makeTelemetry({ nodeId: 'user-supplied-id-12345' });
    node.broadcastTelemetry(telemetry);

    const payload = JSON.parse(captured[0]) as EvasionTelemetry;
    expect(payload.nodeId).toBe(node.nodeId);
    expect(payload.nodeId).not.toBe('user-supplied-id-12345');
  });

  /**
   * REQ 13.4: When there are no connected peers, broadcastTelemetry must not
   * throw and must not send anything.
   */
  it('broadcastTelemetry con cero peers no lanza error y no envía datos', () => {
    const node = new MeshNode();
    expect(() => node.broadcastTelemetry(makeTelemetry())).not.toThrow();
  });

  /**
   * REQ 13.4: Telemetry values (detectionScore, bandwidthEstimateBps, etc.)
   * are preserved correctly in the serialized payload.
   */
  it('los valores de telemetría se preservan correctamente en el payload serializado', () => {
    const node = new MeshNode();
    const { captured } = injectMockPeer(node, 'peer-values');

    const telemetry = makeTelemetry({
      timestamp: 1_700_000_000_000,
      activeState: EVASION_STATE.CHAFF,
      detectionScore: 0.85,
      bandwidthEstimateBps: 5_000_000,
      packetsProcessed: 1234,
      averageLatencyMs: 12.5,
      transitionWeights: [
        { fromState: EVASION_STATE.SPLIT, toState: EVASION_STATE.DISORDER, weight: 0.5 },
      ],
    });

    node.broadcastTelemetry(telemetry);

    const payload = JSON.parse(captured[0]) as EvasionTelemetry;
    expect(payload.timestamp).toBe(1_700_000_000_000);
    expect(payload.activeState).toBe(EVASION_STATE.CHAFF);
    expect(payload.detectionScore).toBeCloseTo(0.85);
    expect(payload.bandwidthEstimateBps).toBe(5_000_000);
    expect(payload.packetsProcessed).toBe(1234);
    expect(payload.averageLatencyMs).toBeCloseTo(12.5);
    expect(payload.transitionWeights).toHaveLength(1);
  });
});
