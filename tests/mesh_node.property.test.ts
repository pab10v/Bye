/**
 * Propiedad 11: Aislamiento del tráfico web real en el mesh
 *
 * Para todo dato transmitido por RTCDataChannel: el dato es únicamente
 * `EvasionTelemetry` y no contiene tráfico web del usuario.
 *
 * Verifica que `broadcastTelemetry` solo serializa los campos de
 * `EvasionTelemetry` (sin URLs, sin payloads HTTP, sin datos identificables).
 *
 * **Valida: Requisito 9.2**
 */
import { describe, it, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import { MeshNode } from '../src/mesh_node.js';
import { EvasionTelemetry, EVASION_STATE, EvasionState, TransitionWeights } from '../src/types.js';

// ---------------------------------------------------------------------------
// Allowed fields in EvasionTelemetry (REQ 9.2)
// ---------------------------------------------------------------------------
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

// Fields that must NEVER appear in the serialized payload
const FORBIDDEN_FIELD_PATTERNS = [
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

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

const evasionStateArb: fc.Arbitrary<EvasionState> = fc.constantFrom(
  EVASION_STATE.SPLIT,
  EVASION_STATE.DISORDER,
  EVASION_STATE.CHAFF,
);

const transitionWeightsArb: fc.Arbitrary<TransitionWeights> = fc.record({
  fromState: evasionStateArb,
  toState: evasionStateArb,
  weight: fc.float({ min: 0, max: 1, noNaN: true }),
});

const evasionTelemetryArb: fc.Arbitrary<EvasionTelemetry> = fc.record({
  nodeId: fc.uuid(),
  timestamp: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
  activeState: evasionStateArb,
  transitionWeights: fc.array(transitionWeightsArb, { minLength: 0, maxLength: 9 }),
  detectionScore: fc.float({ min: 0, max: 1, noNaN: true }),
  bandwidthEstimateBps: fc.integer({ min: 0, max: 1_000_000_000 }),
  packetsProcessed: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
  averageLatencyMs: fc.float({ min: 0, max: 10_000, noNaN: true }),
});

/**
 * Arbitrary that generates an EvasionTelemetry object with extra forbidden
 * fields injected (simulating a polluted input).
 */
const pollutedTelemetryArb: fc.Arbitrary<Record<string, unknown>> = fc.tuple(
  evasionTelemetryArb,
  fc.record({
    url: fc.webUrl(),
    httpPayload: fc.string({ minLength: 1, maxLength: 100 }),
    userEmail: fc.emailAddress(),
    cookie: fc.string({ minLength: 1, maxLength: 50 }),
    requestBody: fc.string({ minLength: 1, maxLength: 100 }),
  }),
).map(([telemetry, forbidden]) => ({
  ...telemetry,
  ...forbidden,
}));

// ---------------------------------------------------------------------------
// Helper: capture what broadcastTelemetry sends over the data channel
// ---------------------------------------------------------------------------

function captureSerializedPayload(telemetry: EvasionTelemetry): string | null {
  const node = new MeshNode();

  let captured: string | null = null;

  // Manually inject a mock peer whose send() captures the serialized string
  const mockChannel = {
    label: 'ppo-mesh-test-peer',
    readyState: 'open' as RTCDataChannelState,
    send(data: string): void {
      captured = data;
    },
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    close: () => {},
    // Remaining RTCDataChannel properties (unused)
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

  // Access the private peers map via type assertion to inject the mock peer
  const peers: Map<string, { peerConnection: null; dataChannel: RTCDataChannel; inactivityTimer: null }> =
    (node as unknown as { peers: Map<string, unknown> }).peers as Map<
      string,
      { peerConnection: null; dataChannel: RTCDataChannel; inactivityTimer: null }
    >;

  peers.set('test-peer', {
    peerConnection: null,
    dataChannel: mockChannel,
    inactivityTimer: null,
  });

  node.broadcastTelemetry(telemetry);

  return captured;
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

describe('Propiedad 11: Aislamiento del tráfico web real en el mesh', () => {
  it(
    'el payload serializado solo contiene los campos permitidos de EvasionTelemetry',
    () => {
      fc.assert(
        fc.property(evasionTelemetryArb, (telemetry) => {
          const serialized = captureSerializedPayload(telemetry);

          // broadcastTelemetry must have sent something
          if (serialized === null) return false;

          const parsed = JSON.parse(serialized) as Record<string, unknown>;
          const keys = Object.keys(parsed);

          // Every key in the serialized payload must be in the allowed set
          return keys.every((key) => ALLOWED_FIELDS.has(key));
        }),
        { numRuns: 200 },
      );
    },
  );

  it(
    'el payload serializado no contiene campos con nombres relacionados a tráfico web o datos de usuario',
    () => {
      fc.assert(
        fc.property(evasionTelemetryArb, (telemetry) => {
          const serialized = captureSerializedPayload(telemetry);
          if (serialized === null) return false;

          const parsed = JSON.parse(serialized) as Record<string, unknown>;
          const keys = Object.keys(parsed);

          // None of the keys should match forbidden patterns
          return keys.every(
            (key) => !FORBIDDEN_FIELD_PATTERNS.some((pattern) => pattern.test(key)),
          );
        }),
        { numRuns: 200 },
      );
    },
  );

  it(
    'cuando el input tiene campos extra (URLs, payloads HTTP), estos son eliminados del payload',
    () => {
      fc.assert(
        fc.property(pollutedTelemetryArb, (polluted) => {
          // Cast to EvasionTelemetry — broadcastTelemetry must sanitize it
          const serialized = captureSerializedPayload(polluted as unknown as EvasionTelemetry);
          if (serialized === null) return false;

          const parsed = JSON.parse(serialized) as Record<string, unknown>;
          const keys = Object.keys(parsed);

          // The forbidden fields must not appear in the output
          const hasForbiddenField = keys.some(
            (key) => !ALLOWED_FIELDS.has(key),
          );
          return !hasForbiddenField;
        }),
        { numRuns: 200 },
      );
    },
  );

  it(
    'el número de campos en el payload serializado es exactamente el número de campos de EvasionTelemetry',
    () => {
      fc.assert(
        fc.property(evasionTelemetryArb, (telemetry) => {
          const serialized = captureSerializedPayload(telemetry);
          if (serialized === null) return false;

          const parsed = JSON.parse(serialized) as Record<string, unknown>;
          return Object.keys(parsed).length === ALLOWED_FIELDS.size;
        }),
        { numRuns: 200 },
      );
    },
  );
});
