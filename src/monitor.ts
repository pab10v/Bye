/**
 * PPO Reactor Monitor — Real-time Forensic Dashboard
 *
 * Connects to the background Service Worker via chrome.runtime.sendMessage
 * and polls every second for live status updates.
 */

interface PPOStatus {
  fsm: {
    currentState: number;
    matrix: number[][];
  };
  pipeline: {
    activeRequests: number;
    degradedMode: boolean;
    memoryUsage: { used: number; limit: number } | null;
    wasmMode?: 'wasm' | 'simulation';
  };
  mesh: {
    nodeId: string;
    mode: string;
    peerCount: number;
  };
  stats: {
    totalBytesProcessed: number;
    totalTransitions: number;
    meshUpdatesReceived: number;
    uptime: number;
  };
  dpi?: {
    score: number;
    level: string;
    dominantSignal: string | null;
    signals: Record<string, number | boolean>;
  };
  probe?: {
    intervalMs: number;
    canaryCount: number;
    lastCycleAt: number | null;
    lastCycleFailures: number;
    latestResults: Array<{
      url: string;
      ttfbMs: number;
      connectionFailed: boolean;
      timestamp: number;
    }>;
    canaryEntries?: Array<{
      url: string;
      isUserDefined: boolean;
      status: 'active' | 'fallback' | 'invalid';
      consecutiveFailures: number;
    }>;
    userCanaryUrls?: string[];
  };
  evaluator?: {
    active: boolean;
    lastGradientUpdateAt: number | null;
    perStateStats: Record<string, { successRate: number; totalOutcomes: number; successCount: number }>;
  };
  chunkIntensity?: string;
  hostFragmentationActive?: boolean;
  timestamp: number;
}

// ── Constants ────────────────────────────────────────────────────────────────

const STATE_NAMES: Record<number, string> = {
  0x01: 'SPLIT',
  0x02: 'DISORDER',
  0x03: 'CHAFF',
};

const STATE_DESCS: Record<number, string> = {
  0x01: 'stochastic SNI fragmentation',
  0x02: 'TCP window manipulation',
  0x03: 'pink noise injection',
};

const STATE_COLORS: Record<number, string> = {
  0x01: '#4cc9f0',
  0x02: '#4361ee',
  0x03: '#f72585',
};

const ROW_LABELS = ['SPLIT', 'DISORD', 'CHAFF'];

const THREAT_LABELS: Record<string, string> = {
  none:     'NO SURVEILLANCE DETECTED',
  low:      'ANOMALY DETECTED — MONITORING',
  medium:   'POSSIBLE DPI MIDDLEBOX',
  high:     'LIKELY UNDER SURVEILLANCE',
  critical: 'ACTIVE DPI CONFIRMED',
};

const SIGNAL_LABELS: Record<string, string> = {
  tlsFailureRate:        'selective TLS failures',
  tlsLatencyOverheadMs:  'TLS handshake overhead',
  latencyJitter:         'latency jitter (DPI CPU)',
  meshPeerScore:         'mesh peer intelligence',
  forcedReassemblyHint:  'forced packet reassembly',
};

// ── State ────────────────────────────────────────────────────────────────────

let lastState: number | null = null;
let lastBytes = 0;
let lastTransitions = 0;
let lastMeshUpdates = 0;
let lastActiveRequests = 0;
let manualOverrideActive = false;

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function el(id: string): HTMLElement | null {
  return document.getElementById(id);
}

function setVal(id: string, val: string) {
  const e = el(id);
  if (e) e.textContent = val;
}

function flashChanged(id: string) {
  const e = el(id);
  if (!e) return;
  e.classList.add('changed');
  setTimeout(() => e.classList.remove('changed'), 600);
}

function formatRate(stats: { successRate: number; totalOutcomes: number } | undefined): string {
  if (!stats || stats.totalOutcomes < 10) return '—';
  return `${Math.round(stats.successRate * 100)}%`;
}

// ── Log ──────────────────────────────────────────────────────────────────────

function addLog(
  message: string,
  type: 'system' | 'tactic' | 'mesh' | 'warning' | 'error' = 'system',
) {
  const logContainer = el('event-log');
  if (!logContainer) return;

  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  entry.textContent = `[${time}] ${message}`;
  logContainer.prepend(entry);

  // Keep only last 60 entries
  while (logContainer.children.length > 60) {
    logContainer.removeChild(logContainer.lastChild!);
  }
}

// ── Matrix rendering ─────────────────────────────────────────────────────────

function renderMatrix(matrix: number[][], currentState: number) {
  const stateIndex = currentState - 1; // 0x01→0, 0x02→1, 0x03→2

  for (let i = 0; i < 3; i++) {
    const rowEl = el(`matrix-row-${i}`);
    if (!rowEl) continue;
    rowEl.innerHTML = '';

    for (let j = 0; j < 3; j++) {
      const val = matrix[i]?.[j] ?? 0;
      const cell = document.createElement('div');
      cell.className = 'matrix-cell';
      cell.textContent = val.toFixed(2);

      // Highlight the active row (current state's outgoing transitions)
      const opacity = 0.05 + val * 0.85;
      if (i === stateIndex) {
        cell.style.backgroundColor = `rgba(76, 201, 240, ${opacity})`;
        cell.style.color = val > 0.5 ? '#fff' : 'var(--text-dim)';
        if (j === stateIndex) cell.classList.add('highlight');
      } else {
        cell.style.backgroundColor = `rgba(67, 97, 238, ${opacity * 0.6})`;
        cell.style.color = 'var(--text-dim)';
      }

      rowEl.appendChild(cell);
    }
  }
}

// ── Threat indicator ─────────────────────────────────────────────────────────

let lastThreatLevel = 'none';

function updateThreatIndicator(dpi?: PPOStatus['dpi']) {
  const banner = el('threat-banner');
  const label  = el('threat-label');
  const signal = el('threat-signal');
  const score  = el('threat-score');
  if (!banner || !label || !signal || !score) return;

  const level         = dpi?.level ?? 'none';
  const scoreVal      = dpi?.score ?? 0;
  const dominant      = dpi?.dominantSignal ?? null;

  // Update classes
  banner.className = `threat-banner threat-${level}`;

  label.textContent = THREAT_LABELS[level] ?? 'UNKNOWN';
  score.textContent = `${Math.round(scoreVal * 100)}%`;
  signal.textContent = dominant ? `↑ ${SIGNAL_LABELS[dominant] ?? dominant}` : '';

  // Log level changes
  if (level !== lastThreatLevel) {
    const logType = level === 'none' ? 'system'
      : level === 'low' || level === 'medium' ? 'warning'
      : 'error';
    addLog(
      `Threat level → ${level.toUpperCase()}: ${THREAT_LABELS[level]}` +
      (dominant ? ` [${SIGNAL_LABELS[dominant] ?? dominant}]` : ''),
      logType,
    );
    lastThreatLevel = level;
  }
}

// ── Tactic buttons ───────────────────────────────────────────────────────────

function updateTacticButtons(currentState: number) {
  document.querySelectorAll('.tactic-btn').forEach((btn) => {
    const btnState = parseInt(btn.getAttribute('data-state') || '0');
    btn.classList.toggle('active-tactic', btnState === currentState && manualOverrideActive);
  });
}

// ── Canary URL list rendering ─────────────────────────────────────────────────

type CanaryEntry = {
  url: string;
  isUserDefined: boolean;
  status: 'active' | 'fallback' | 'invalid';
  consecutiveFailures: number;
};

function renderCanaryList(entries: CanaryEntry[], userUrls: string[]) {
  const listEl = el('canary-url-list');
  if (!listEl) return;

  if (entries.length === 0) {
    listEl.innerHTML = '<div class="canary-url-row"><span class="canary-url-text" style="color:var(--text-dim)">Using hardwired defaults</span></div>';
    return;
  }

  listEl.innerHTML = entries.map((entry, i) => {
    const dotClass = `canary-status-dot ${entry.status}`;
    const fallbackLabel = entry.status === 'fallback'
      ? '<span class="canary-fallback-label">(fallback: hardwired)</span>'
      : '';
    const removeBtn = entry.isUserDefined
      ? `<button class="canary-remove-btn" data-index="${i}" title="Remove">×</button>`
      : '';
    return `
      <div class="canary-url-row">
        <div class="${dotClass}"></div>
        <span class="canary-url-text" title="${entry.url}">${entry.url}</span>
        ${fallbackLabel}
        ${removeBtn}
      </div>
    `;
  }).join('');

  // Attach remove button handlers
  listEl.querySelectorAll('.canary-remove-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.getAttribute('data-index') ?? '-1');
      if (idx < 0) return;
      const newUrls = [...userUrls];
      newUrls.splice(idx, 1);
      try {
        const resp = await chrome.runtime.sendMessage({
          action: 'SET_USER_CANARY_URLS',
          urls: newUrls,
        });
        if (resp?.errors?.length) {
          showCanaryError(resp.errors.join('; '));
        } else {
          hideCanaryError();
          addLog(`Canary URL removed`, 'system');
          refreshStatus();
        }
      } catch {
        addLog('Failed to remove canary URL', 'error');
      }
    });
  });
}

function showCanaryError(msg: string) {
  const errEl = el('canary-url-error');
  if (!errEl) return;
  errEl.textContent = msg;
  errEl.classList.remove('hidden');
}

function hideCanaryError() {
  const errEl = el('canary-url-error');
  if (errEl) errEl.classList.add('hidden');
}

// ── Main UI update ───────────────────────────────────────────────────────────

function updateUI(status: PPOStatus) {
  const state = status.fsm.currentState;

  // ── Activity pulse ──
  const pulseEl = el('activity-pulse');
  if (pulseEl) {
    const hasActivity =
      status.stats.totalBytesProcessed > lastBytes ||
      status.pipeline.activeRequests > 0;
    pulseEl.classList.toggle('active', hasActivity);
  }

  // ── Engine badge ──
  const engineBadge = el('engine-badge');
  if (engineBadge) {
    const mode = status.pipeline.wasmMode;
    if (mode === 'wasm') {
      engineBadge.textContent = 'WASM ✓';
      engineBadge.className = 'engine-badge engine-wasm';
    } else if (mode === 'simulation') {
      engineBadge.textContent = 'SIM MODE';
      engineBadge.className = 'engine-badge engine-sim';
    } else {
      engineBadge.textContent = 'ENGINE';
      engineBadge.className = 'engine-badge engine-unknown';
    }
  }

  // ── FSM state label ──
  const stateLabelEl = el('fsm-state-label');
  const stateDescEl = el('fsm-state-desc');
  if (stateLabelEl) {
    stateLabelEl.textContent = STATE_NAMES[state] ?? 'UNKNOWN';
    stateLabelEl.style.color = STATE_COLORS[state] ?? '#fff';
  }
  if (stateDescEl) {
    stateDescEl.textContent = STATE_DESCS[state] ?? '';
  }

  // Log tactic change
  if (lastState !== null && lastState !== state) {
    stateLabelEl?.parentElement?.classList.add('pulse');
    setTimeout(() => stateLabelEl?.parentElement?.classList.remove('pulse'), 500);
    addLog(`Tactic shift → ${STATE_NAMES[state]}: ${STATE_DESCS[state]}`, 'tactic');
  }
  lastState = state;

  // ── Transition matrix ──
  renderMatrix(status.fsm.matrix, state);
  updateTacticButtons(state);

  // ── Stats ──
  if (status.stats.totalBytesProcessed !== lastBytes) {
    setVal('total-bytes', formatBytes(status.stats.totalBytesProcessed));
    flashChanged('total-bytes');
  }
  lastBytes = status.stats.totalBytesProcessed;

  if (status.stats.totalTransitions !== lastTransitions) {
    setVal('total-transitions', status.stats.totalTransitions.toLocaleString());
    flashChanged('total-transitions');
  }
  lastTransitions = status.stats.totalTransitions;

  if (status.pipeline.activeRequests !== lastActiveRequests) {
    setVal('active-requests', status.pipeline.activeRequests.toString());
    if (status.pipeline.activeRequests > 0) flashChanged('active-requests');
  }
  lastActiveRequests = status.pipeline.activeRequests;

  setVal('peer-count', status.mesh.peerCount.toString());
  setVal('uptime', formatUptime(status.stats.uptime));

  if (status.stats.meshUpdatesReceived !== lastMeshUpdates) {
    setVal('mesh-updates', status.stats.meshUpdatesReceived.toLocaleString());
    addLog(`Intelligence update from mesh peer (mode: ${status.mesh.mode})`, 'mesh');
    flashChanged('mesh-updates');
  }
  lastMeshUpdates = status.stats.meshUpdatesReceived;

  // ── Degraded mode warning ──
  if (status.pipeline.degradedMode) {
    addLog('⚠ Memory limit reached — degraded mode active (no obfuscation)', 'warning');
  }

  // ── DPI threat indicator ──
  updateThreatIndicator(status.dpi);

  // ── CensorshipProbe section ──
  if (status.probe) {
    setVal('probe-interval', `${Math.round(status.probe.intervalMs / 1000)}s`);
    setVal('probe-canary-count', status.probe.canaryCount.toString());
    setVal('probe-failures', status.probe.lastCycleFailures.toString());
    setVal('probe-last-cycle', status.probe.lastCycleAt
      ? new Date(status.probe.lastCycleAt).toLocaleTimeString()
      : 'Never');

    const resultsEl = el('probe-results');
    if (resultsEl && status.probe.latestResults.length > 0) {
      resultsEl.innerHTML = status.probe.latestResults.map(r => {
        const hostname = (() => { try { return new URL(r.url).hostname; } catch { return r.url; } })();
        return `<div class="log-entry ${r.connectionFailed ? 'error' : 'system'}">${hostname}: ${r.connectionFailed ? 'BLOCKED' : `${Math.round(r.ttfbMs)}ms`}</div>`;
      }).join('');
    }

    // Render canary URL management list
    if (status.probe.canaryEntries) {
      renderCanaryList(status.probe.canaryEntries, status.probe.userCanaryUrls ?? []);
    }
  }

  // ── Strategy Evaluator section ──
  if (status.evaluator) {
    const stats = status.evaluator.perStateStats;
    setVal('eval-rate-split',    formatRate(stats['1'] ?? stats[1 as any]));
    setVal('eval-rate-disorder', formatRate(stats['2'] ?? stats[2 as any]));
    setVal('eval-rate-chaff',    formatRate(stats['3'] ?? stats[3 as any]));
    setVal('eval-last-update', status.evaluator.lastGradientUpdateAt
      ? new Date(status.evaluator.lastGradientUpdateAt).toLocaleTimeString()
      : 'Never');
    const badge = el('evaluator-status-badge');
    if (badge) badge.textContent = status.evaluator.active ? 'ACTIVE' : 'PAUSED';
  }

  // ── Chunk Intensity ──
  if (status.chunkIntensity) {
    const label = el('chunk-intensity-label');
    if (label) label.textContent = status.chunkIntensity.toUpperCase();
  }
}

// ── Polling ──────────────────────────────────────────────────────────────────

async function refreshStatus() {
  try {
    const response: PPOStatus = await chrome.runtime.sendMessage({ action: 'GET_PPO_STATUS' });
    if (response) updateUI(response);
  } catch (err) {
    // SW may be waking up — log once, don't spam
    console.warn('[Monitor] Failed to fetch status:', err);
  }
}

// ── Tactical Override buttons ─────────────────────────────────────────────────

document.querySelectorAll('.tactic-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const state = parseInt(btn.getAttribute('data-state') || '1');
    try {
      await chrome.runtime.sendMessage({ action: 'FORCE_TACTIC', state });
      manualOverrideActive = true;

      const notice = el('override-notice');
      if (notice) notice.classList.remove('hidden');

      addLog(
        `Manual override → ${STATE_NAMES[state]}: ${STATE_DESCS[state]}`,
        'system',
      );
      updateTacticButtons(state);
      refreshStatus();
    } catch (err) {
      addLog('Failed to apply override — engine may be restarting', 'error');
    }
  });
});

// ── Strategy Evaluator controls ──────────────────────────────────────────────

el('btn-toggle-evaluator')?.addEventListener('click', async () => {
  try {
    const resp = await chrome.runtime.sendMessage({ action: 'TOGGLE_STRATEGY_EVALUATOR' });
    const isActive: boolean = resp?.active ?? false;
    const badge = el('evaluator-status-badge');
    const btnSpan = el('btn-toggle-evaluator')?.querySelector('span:nth-child(2)');
    if (badge) badge.textContent = isActive ? 'ACTIVE' : 'PAUSED';
    if (btnSpan) btnSpan.textContent = isActive ? 'Pause' : 'Resume';
    addLog(`Strategy Evaluator ${isActive ? 'resumed' : 'paused'}`, 'system');
  } catch {
    addLog('Failed to toggle Strategy Evaluator', 'error');
  }
});

el('btn-reset-evaluator')?.addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ action: 'RESET_STRATEGY_EVALUATOR' });
    addLog('Strategy Evaluator reset — TransitionMatrix restored to uniform distribution', 'system');
    refreshStatus();
  } catch {
    addLog('Failed to reset Strategy Evaluator', 'error');
  }
});

// ── Chunk Intensity toggle ────────────────────────────────────────────────────

el('btn-chunk-intensity')?.addEventListener('click', async () => {
  const currentLabel = el('chunk-intensity-label')?.textContent?.toLowerCase() ?? 'mild';
  const next = currentLabel === 'mild' ? 'aggressive' : 'mild';
  try {
    await chrome.runtime.sendMessage({ action: 'SET_CHUNK_INTENSITY', intensity: next });
    const label = el('chunk-intensity-label');
    if (label) label.textContent = next.toUpperCase();
    addLog(`Chunk intensity → ${next.toUpperCase()}`, 'tactic');
  } catch {
    addLog('Failed to update chunk intensity', 'error');
  }
});

// ── Canary URL event handlers ─────────────────────────────────────────────────

el('btn-canary-add')?.addEventListener('click', async () => {
  const input = el('canary-url-input') as HTMLInputElement | null;
  const newUrl = input?.value?.trim() ?? '';
  if (!newUrl) return;

  try {
    // Get current user URLs from the latest status
    const statusResp: PPOStatus = await chrome.runtime.sendMessage({ action: 'GET_PPO_STATUS' });
    const currentUrls = statusResp?.probe?.userCanaryUrls ?? [];
    const updatedUrls = [...currentUrls, newUrl];

    const resp = await chrome.runtime.sendMessage({
      action: 'SET_USER_CANARY_URLS',
      urls: updatedUrls,
    });

    if (resp?.errors?.length) {
      showCanaryError(resp.errors.join('; '));
    } else {
      hideCanaryError();
      if (input) input.value = '';
      addLog(`Canary URL added: ${newUrl}`, 'system');
      refreshStatus();
    }
  } catch {
    addLog('Failed to add canary URL', 'error');
  }
});

el('canary-url-input')?.addEventListener('keydown', async (e) => {
  if ((e as KeyboardEvent).key === 'Enter') {
    el('btn-canary-add')?.dispatchEvent(new MouseEvent('click'));
  }
});

el('btn-canary-reset')?.addEventListener('click', async () => {
  try {
    const resp = await chrome.runtime.sendMessage({
      action: 'SET_USER_CANARY_URLS',
      urls: [],
    });
    if (resp?.errors?.length) {
      showCanaryError(resp.errors.join('; '));
    } else {
      hideCanaryError();
      addLog('Canary URLs reset to hardwired defaults', 'system');
      refreshStatus();
    }
  } catch {
    addLog('Failed to reset canary URLs', 'error');
  }
});

// ── Boot ─────────────────────────────────────────────────────────────────────

addLog('Monitor connected. Polling engine...', 'system');
refreshStatus();
setInterval(refreshStatus, 1000);
