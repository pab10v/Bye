import { describe, it, expect, beforeEach } from 'vitest';
import { BypassManager, createBypassManager } from '../src/bypass_manager.js';

// ---------------------------------------------------------------------------
// Unit tests for BypassManager — task 8.3
// Requirements: 1.2, 1.4
// ---------------------------------------------------------------------------

describe('BypassManager', () => {
  // -------------------------------------------------------------------------
  // Empty list
  // -------------------------------------------------------------------------
  describe('empty rule list', () => {
    it('returns false for any URL when no rules are configured', () => {
      const bm = createBypassManager();
      expect(bm.shouldBypass('https://google.com')).toBe(false);
      expect(bm.shouldBypass('https://mail.google.com')).toBe(false);
      expect(bm.shouldBypass('http://192.168.0.1')).toBe(false);
      expect(bm.shouldBypass('localhost')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Glob pattern matching
  // -------------------------------------------------------------------------
  describe('glob pattern *.google.com', () => {
    let bm: BypassManager;

    beforeEach(() => {
      bm = createBypassManager(['*.google.com']);
    });

    it('matches mail.google.com', () => {
      expect(bm.shouldBypass('https://mail.google.com')).toBe(true);
    });

    it('matches accounts.google.com', () => {
      expect(bm.shouldBypass('https://accounts.google.com/login')).toBe(true);
    });

    it('does NOT match google.com (no subdomain)', () => {
      expect(bm.shouldBypass('https://google.com')).toBe(false);
    });

    it('does NOT match google.com.evil.com (suffix attack)', () => {
      expect(bm.shouldBypass('https://google.com.evil.com')).toBe(false);
    });

    it('does NOT match sub.mail.google.com (two-level subdomain)', () => {
      // *.google.com only matches one subdomain level
      expect(bm.shouldBypass('https://sub.mail.google.com')).toBe(false);
    });

    it('does NOT match notgoogle.com', () => {
      expect(bm.shouldBypass('https://notgoogle.com')).toBe(false);
    });
  });

  describe('exact domain match google.com', () => {
    let bm: BypassManager;

    beforeEach(() => {
      bm = createBypassManager(['google.com']);
    });

    it('matches google.com exactly', () => {
      expect(bm.shouldBypass('https://google.com')).toBe(true);
    });

    it('does NOT match mail.google.com', () => {
      expect(bm.shouldBypass('https://mail.google.com')).toBe(false);
    });
  });

  describe('special token <local>', () => {
    it('matches the literal string <local>', () => {
      const bm = createBypassManager(['<local>']);
      expect(bm.shouldBypass('<local>')).toBe(true);
    });
  });

  describe('localhost rule', () => {
    it('matches localhost', () => {
      const bm = createBypassManager(['localhost']);
      expect(bm.shouldBypass('http://localhost')).toBe(true);
      expect(bm.shouldBypass('http://localhost:8080/path')).toBe(true);
    });

    it('does NOT match localhostevil.com', () => {
      const bm = createBypassManager(['localhost']);
      expect(bm.shouldBypass('https://localhostevil.com')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // CIDR range matching
  // -------------------------------------------------------------------------
  describe('CIDR range 192.168.0.0/24', () => {
    let bm: BypassManager;

    beforeEach(() => {
      bm = createBypassManager(['192.168.0.0/24']);
    });

    it('matches 192.168.0.1', () => {
      expect(bm.shouldBypass('http://192.168.0.1')).toBe(true);
    });

    it('matches 192.168.0.254', () => {
      expect(bm.shouldBypass('http://192.168.0.254')).toBe(true);
    });

    it('matches 192.168.0.0 (network address)', () => {
      expect(bm.shouldBypass('http://192.168.0.0')).toBe(true);
    });

    it('does NOT match 192.168.1.1 (different subnet)', () => {
      expect(bm.shouldBypass('http://192.168.1.1')).toBe(false);
    });

    it('does NOT match 10.0.0.1 (different network)', () => {
      expect(bm.shouldBypass('http://10.0.0.1')).toBe(false);
    });
  });

  describe('CIDR range 10.0.0.0/8', () => {
    let bm: BypassManager;

    beforeEach(() => {
      bm = createBypassManager(['10.0.0.0/8']);
    });

    it('matches 10.0.0.1', () => {
      expect(bm.shouldBypass('http://10.0.0.1')).toBe(true);
    });

    it('matches 10.255.255.255', () => {
      expect(bm.shouldBypass('http://10.255.255.255')).toBe(true);
    });

    it('does NOT match 11.0.0.1', () => {
      expect(bm.shouldBypass('http://11.0.0.1')).toBe(false);
    });
  });

  describe('CIDR /32 (single host)', () => {
    it('matches only the exact IP', () => {
      const bm = createBypassManager(['192.168.1.100/32']);
      expect(bm.shouldBypass('http://192.168.1.100')).toBe(true);
      expect(bm.shouldBypass('http://192.168.1.101')).toBe(false);
    });
  });

  describe('CIDR /0 (match all IPs)', () => {
    it('matches any IP address', () => {
      const bm = createBypassManager(['0.0.0.0/0']);
      expect(bm.shouldBypass('http://1.2.3.4')).toBe(true);
      expect(bm.shouldBypass('http://255.255.255.255')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // addRule / removeRule
  // -------------------------------------------------------------------------
  describe('addRule and removeRule', () => {
    it('addRule adds a new pattern', () => {
      const bm = createBypassManager();
      expect(bm.shouldBypass('https://example.com')).toBe(false);
      bm.addRule('example.com');
      expect(bm.shouldBypass('https://example.com')).toBe(true);
    });

    it('addRule ignores duplicate patterns', () => {
      const bm = createBypassManager();
      bm.addRule('example.com');
      bm.addRule('example.com');
      expect(bm.getRuleCount()).toBe(1);
    });

    it('removeRule removes an existing pattern', () => {
      const bm = createBypassManager(['example.com']);
      expect(bm.shouldBypass('https://example.com')).toBe(true);
      bm.removeRule('example.com');
      expect(bm.shouldBypass('https://example.com')).toBe(false);
    });

    it('removeRule is a no-op for non-existent pattern', () => {
      const bm = createBypassManager(['example.com']);
      expect(() => bm.removeRule('nonexistent.com')).not.toThrow();
      expect(bm.getRuleCount()).toBe(1);
    });

    it('addRule trims whitespace', () => {
      const bm = createBypassManager();
      bm.addRule('  example.com  ');
      expect(bm.shouldBypass('https://example.com')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Multiple rules
  // -------------------------------------------------------------------------
  describe('multiple rules', () => {
    it('returns true if URL matches any rule', () => {
      const bm = createBypassManager(['*.google.com', '192.168.0.0/24', 'localhost']);
      expect(bm.shouldBypass('https://mail.google.com')).toBe(true);
      expect(bm.shouldBypass('http://192.168.0.5')).toBe(true);
      expect(bm.shouldBypass('http://localhost')).toBe(true);
    });

    it('returns false if URL matches no rule', () => {
      const bm = createBypassManager(['*.google.com', '192.168.0.0/24']);
      expect(bm.shouldBypass('https://example.com')).toBe(false);
      expect(bm.shouldBypass('http://10.0.0.1')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Determinism
  // -------------------------------------------------------------------------
  describe('determinism', () => {
    it('same URL + same rules always returns the same result', () => {
      const bm = createBypassManager(['*.google.com', '192.168.0.0/24']);
      const url = 'https://mail.google.com';
      const results = Array.from({ length: 10 }, () => bm.shouldBypass(url));
      expect(results.every(r => r === true)).toBe(true);
    });

    it('same URL + same rules returns false consistently', () => {
      const bm = createBypassManager(['*.google.com']);
      const url = 'https://evil.com';
      const results = Array.from({ length: 10 }, () => bm.shouldBypass(url));
      expect(results.every(r => r === false)).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // URL format handling
  // -------------------------------------------------------------------------
  describe('URL format handling', () => {
    it('handles URLs with paths and query strings', () => {
      const bm = createBypassManager(['example.com']);
      expect(bm.shouldBypass('https://example.com/path?q=1#hash')).toBe(true);
    });

    it('handles bare hostnames without protocol', () => {
      const bm = createBypassManager(['example.com']);
      expect(bm.shouldBypass('example.com')).toBe(true);
    });

    it('handles http:// and https:// protocols', () => {
      const bm = createBypassManager(['example.com']);
      expect(bm.shouldBypass('http://example.com')).toBe(true);
      expect(bm.shouldBypass('https://example.com')).toBe(true);
    });

    it('is case-insensitive for hostnames', () => {
      const bm = createBypassManager(['example.com']);
      expect(bm.shouldBypass('https://EXAMPLE.COM')).toBe(true);
      expect(bm.shouldBypass('https://Example.Com')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // initialRules constructor parameter
  // -------------------------------------------------------------------------
  describe('constructor initialRules', () => {
    it('accepts initial rules via constructor', () => {
      const bm = new BypassManager(['*.google.com', '192.168.0.0/24']);
      expect(bm.shouldBypass('https://mail.google.com')).toBe(true);
      expect(bm.shouldBypass('http://192.168.0.1')).toBe(true);
      expect(bm.shouldBypass('https://evil.com')).toBe(false);
    });
  });
});
