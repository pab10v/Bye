/**
 * BypassManager — evaluates whether a URL should bypass the obfuscation pipeline.
 *
 * Supports two pattern types:
 *   1. Glob patterns  — e.g. `*.google.com`, `google.com`, `<local>`
 *   2. CIDR ranges    — e.g. `192.168.0.0/24`, `10.0.0.0/8`
 *
 * Requirements: 1.2, 1.3, 1.4
 */

// ---------------------------------------------------------------------------
// Glob helpers
// ---------------------------------------------------------------------------

/**
 * Convert a glob pattern (supporting only `*` as wildcard) to a RegExp.
 *
 * Rules:
 *   - `*.google.com`  → matches `mail.google.com` but NOT `google.com.evil.com`
 *   - `google.com`    → exact domain match
 *   - `<local>`       → special Chrome bypass token, matches as-is
 *   - `localhost`     → exact match
 *
 * The `*` wildcard matches one or more characters that are NOT a dot, so that
 * `*.google.com` cannot be satisfied by `google.com` (no subdomain) or by
 * `evil.google.com.attacker.com` (extra suffix).
 */
function globToRegex(pattern: string): RegExp {
  // Escape all regex special characters except `*`
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // Replace `*` with a group that matches one or more non-dot characters
  const regexStr = escaped.replace(/\*/g, '[^.]+');
  return new RegExp(`^${regexStr}$`, 'i');
}

// ---------------------------------------------------------------------------
// CIDR helpers
// ---------------------------------------------------------------------------

/**
 * Parse an IPv4 address string into a 32-bit unsigned integer.
 * Returns NaN if the string is not a valid IPv4 address.
 */
function ipv4ToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return NaN;
  let result = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return NaN;
    result = (result * 256 + octet) >>> 0;
  }
  return result;
}

/**
 * Returns true if `ip` falls within the CIDR range `cidr`.
 * Both `ip` and the network address in `cidr` must be valid IPv4 addresses.
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  const slashIdx = cidr.indexOf('/');
  if (slashIdx === -1) return false;

  const networkStr = cidr.slice(0, slashIdx);
  const prefixLen = parseInt(cidr.slice(slashIdx + 1), 10);

  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;

  const ipInt = ipv4ToInt(ip);
  const networkInt = ipv4ToInt(networkStr);

  if (isNaN(ipInt) || isNaN(networkInt)) return false;

  if (prefixLen === 0) {
    // /0 matches everything
    return true;
  }

  // Build the mask: e.g. /24 → 0xFFFFFF00
  const mask = (0xffffffff << (32 - prefixLen)) >>> 0;

  return (ipInt & mask) >>> 0 === (networkInt & mask) >>> 0;
}

// ---------------------------------------------------------------------------
// Pattern classification
// ---------------------------------------------------------------------------

/** Returns true if the pattern looks like a CIDR range (e.g. `192.168.0.0/24`). */
function isCidrPattern(pattern: string): boolean {
  return /^[\d.]+\/\d+$/.test(pattern);
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/**
 * Extract the hostname from a URL string.
 *
 * Handles:
 *   - Full URLs with protocol: `https://mail.google.com/path`
 *   - Protocol-relative: `//mail.google.com/path`
 *   - Bare hostnames / IPs: `mail.google.com`, `192.168.0.1`
 */
function extractHostname(url: string): string {
  // Try the URL constructor first (handles http:// and https://)
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    // Not a full URL — treat the whole string as a hostname (strip any path)
    const withoutPath = url.split('/')[0];
    // Strip port if present
    const withoutPort = withoutPath.split(':')[0];
    return withoutPort.toLowerCase();
  }
}

// ---------------------------------------------------------------------------
// BypassManager
// ---------------------------------------------------------------------------

export class BypassManager {
  private readonly rules: Set<string> = new Set();

  constructor(initialRules: string[] = []) {
    for (const rule of initialRules) {
      this.addRule(rule);
    }
  }

  /** Add a bypass rule (glob pattern or CIDR range). Duplicates are ignored. */
  addRule(pattern: string): void {
    const trimmed = pattern.trim();
    if (trimmed.length > 0) {
      this.rules.add(trimmed);
    }
  }

  /** Remove a bypass rule. No-op if the rule does not exist. */
  removeRule(pattern: string): void {
    this.rules.delete(pattern.trim());
  }

  /**
   * Returns true if `url` matches any rule in the bypass list.
   *
   * Evaluation is deterministic: same URL + same rule set → same result.
   * If the rule list is empty, always returns false.
   */
  shouldBypass(url: string): boolean {
    if (this.rules.size === 0) {
      return false;
    }

    const hostname = extractHostname(url);

    for (const rule of this.rules) {
      if (isCidrPattern(rule)) {
        // CIDR match: compare the hostname (must be an IP) against the range
        if (isIpInCidr(hostname, rule)) {
          return true;
        }
      } else {
        // Glob / exact match
        const regex = globToRegex(rule);
        if (regex.test(hostname)) {
          return true;
        }
      }
    }

    return false;
  }

  /** Returns the current number of rules. */
  getRuleCount(): number {
    return this.rules.size;
  }
}

/**
 * Factory function — creates a fresh BypassManager instance.
 */
export function createBypassManager(initialRules: string[] = []): BypassManager {
  return new BypassManager(initialRules);
}
