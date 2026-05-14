/**
 * Propiedad 6: Evaluación correcta de la lista de bypass
 *
 * Para toda URL y todo conjunto de patrones en la lista de bypass:
 * - Si la URL coincide con algún patrón: shouldBypass = true
 * - Si no coincide con ningún patrón: shouldBypass = false
 * - La clasificación es consistente: misma URL + mismos patrones → mismo resultado
 *
 * **Validates: Requirements 1.2, 1.3**
 */
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { createBypassManager } from '../src/bypass_manager.js';

// ---------------------------------------------------------------------------
// Arbitrary generators
// ---------------------------------------------------------------------------

/**
 * Generates a valid hostname label (letters and digits only).
 * Constrained to ASCII to keep tests deterministic and avoid Unicode edge cases.
 */
const arbHostnameLabel: fc.Arbitrary<string> = fc
  .stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'), {
    minLength: 1,
    maxLength: 10,
  });

/**
 * Generates a valid TLD label (letters only, no digits) so that the resulting
 * hostname is parseable by `new URL()`. A purely numeric TLD (e.g. ".1") causes
 * URL parsing to fail, which breaks the extractHostname fallback path.
 */
const arbTldLabel: fc.Arbitrary<string> = fc
  .stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), {
    minLength: 2,
    maxLength: 6,
  });

/**
 * Generates a valid hostname with 1–3 labels where the last label (TLD) is
 * alphabetic-only (e.g. "example.com", "mail.example.com", "a.b.org").
 * This ensures `new URL('https://<hostname>')` succeeds.
 */
const arbHostname: fc.Arbitrary<string> = fc
  .tuple(
    fc.array(arbHostnameLabel, { minLength: 0, maxLength: 2 }),
    arbTldLabel,
  )
  .map(([labels, tld]) => [...labels, tld].join('.'));

/**
 * Generates a full URL with http or https scheme and an optional path.
 */
const arbUrl: fc.Arbitrary<string> = fc.record({
  scheme: fc.constantFrom('http', 'https'),
  hostname: arbHostname,
  path: fc.constantFrom('', '/path', '/a/b/c', '/path?q=1'),
}).map(({ scheme, hostname, path }) => `${scheme}://${hostname}${path}`);

/**
 * Generates an exact-domain glob pattern (no wildcard) matching a specific hostname.
 * The pattern is derived from the URL's hostname so we can assert shouldBypass = true.
 */
function exactPatternFor(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url.split('/')[0].split(':')[0].toLowerCase();
  }
}

/**
 * Generates a wildcard glob pattern `*.parent` that matches `sub.parent` hostnames.
 * Given a hostname like "mail.example.com", produces "*.example.com".
 * Returns null if the hostname has fewer than 2 labels (no parent to wildcard).
 */
function wildcardPatternFor(hostname: string): string | null {
  const labels = hostname.split('.');
  if (labels.length < 2) return null;
  return `*.${labels.slice(1).join('.')}`;
}

/**
 * Generates a list of glob patterns that are guaranteed NOT to match the given URL.
 * We use a fixed "unrelated" domain that will never appear in generated URLs.
 */
const arbNonMatchingPatterns: fc.Arbitrary<string[]> = fc
  .array(
    fc.constantFrom(
      'unrelated-domain-xyz.com',
      '*.unrelated-xyz.net',
      'no-match-ever.org',
      '*.no-match-ever.io',
    ),
    { minLength: 1, maxLength: 4 },
  );

// ---------------------------------------------------------------------------
// Property 6a: Consistency — same URL + same patterns → same result
// ---------------------------------------------------------------------------

describe('Propiedad 6a: Consistencia de la evaluación de bypass', () => {
  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * For every URL and every set of patterns, calling shouldBypass multiple times
   * with the same inputs always returns the same boolean result.
   */
  it('misma URL + mismos patrones → mismo resultado en todas las invocaciones', () => {
    fc.assert(
      fc.property(
        arbUrl,
        arbNonMatchingPatterns,
        (url: string, patterns: string[]) => {
          const bm = createBypassManager(patterns);

          // Call shouldBypass 5 times and verify all results are identical
          const results = Array.from({ length: 5 }, () => bm.shouldBypass(url));
          const first = results[0];
          return results.every((r) => r === first);
        },
      ),
      { numRuns: 500 },
    );
  });

  it('consistencia se mantiene tras addRule y removeRule', () => {
    fc.assert(
      fc.property(
        arbUrl,
        arbHostname,
        (url: string, extraPattern: string) => {
          const bm = createBypassManager([]);

          bm.addRule(extraPattern);
          const result1 = bm.shouldBypass(url);
          const result2 = bm.shouldBypass(url);

          if (result1 !== result2) return false;

          bm.removeRule(extraPattern);
          const result3 = bm.shouldBypass(url);
          const result4 = bm.shouldBypass(url);

          return result3 === result4;
        },
      ),
      { numRuns: 300 },
    );
  });
});

// ---------------------------------------------------------------------------
// Property 6b: Correctness — matching URL → shouldBypass = true
// ---------------------------------------------------------------------------

describe('Propiedad 6b: URL que coincide con un patrón → shouldBypass = true', () => {
  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * For every URL whose hostname exactly matches a pattern in the bypass list,
   * shouldBypass must return true.
   */
  it('URL con hostname exacto en la lista → shouldBypass = true', () => {
    fc.assert(
      fc.property(
        arbUrl,
        (url: string) => {
          const exactPattern = exactPatternFor(url);
          const bm = createBypassManager([exactPattern]);
          return bm.shouldBypass(url) === true;
        },
      ),
      { numRuns: 500 },
    );
  });

  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * For every URL with a multi-label hostname (e.g. "mail.example.com"),
   * a wildcard pattern "*.example.com" must match it → shouldBypass = true.
   */
  it('URL con subdominio que coincide con patrón glob *.parent → shouldBypass = true', () => {
    fc.assert(
      fc.property(
        // Generate a hostname with at least 2 labels (subdomain + TLD) so wildcard is applicable.
        // The TLD must be alphabetic-only so new URL() can parse it successfully.
        fc.tuple(
          fc.array(arbHostnameLabel, { minLength: 1, maxLength: 2 }),
          arbTldLabel,
        ).map(([labels, tld]) => [...labels, tld].join('.')),
        (hostname: string) => {
          const wildcardPattern = wildcardPatternFor(hostname);
          if (wildcardPattern === null) return true; // skip if not applicable

          const url = `https://${hostname}/path`;
          const bm = createBypassManager([wildcardPattern]);
          return bm.shouldBypass(url) === true;
        },
      ),
      { numRuns: 500 },
    );
  });

  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * The matching pattern can be anywhere in a list of multiple patterns.
   * As long as at least one pattern matches, shouldBypass must be true.
   */
  it('URL que coincide con al menos un patrón en una lista mixta → shouldBypass = true', () => {
    fc.assert(
      fc.property(
        arbUrl,
        arbNonMatchingPatterns,
        (url: string, nonMatchingPatterns: string[]) => {
          const matchingPattern = exactPatternFor(url);
          // Insert the matching pattern at a random position in the list
          const patterns = [...nonMatchingPatterns, matchingPattern];
          const bm = createBypassManager(patterns);
          return bm.shouldBypass(url) === true;
        },
      ),
      { numRuns: 500 },
    );
  });
});

// ---------------------------------------------------------------------------
// Property 6c: Correctness — non-matching URL → shouldBypass = false
// ---------------------------------------------------------------------------

describe('Propiedad 6c: URL que no coincide con ningún patrón → shouldBypass = false', () => {
  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * For every URL that does not match any pattern in the bypass list,
   * shouldBypass must return false.
   */
  it('URL que no coincide con ningún patrón en la lista → shouldBypass = false', () => {
    fc.assert(
      fc.property(
        arbUrl,
        arbNonMatchingPatterns,
        (url: string, patterns: string[]) => {
          const bm = createBypassManager(patterns);
          return bm.shouldBypass(url) === false;
        },
      ),
      { numRuns: 500 },
    );
  });

  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * An empty bypass list must never classify any URL as bypass.
   */
  it('lista de bypass vacía → shouldBypass = false para toda URL', () => {
    fc.assert(
      fc.property(
        arbUrl,
        (url: string) => {
          const bm = createBypassManager([]);
          return bm.shouldBypass(url) === false;
        },
      ),
      { numRuns: 500 },
    );
  });

  /**
   * **Validates: Requirements 1.2, 1.3**
   *
   * After removing the only matching rule, the URL must no longer be bypassed.
   */
  it('tras removeRule del único patrón coincidente → shouldBypass = false', () => {
    fc.assert(
      fc.property(
        arbUrl,
        (url: string) => {
          const matchingPattern = exactPatternFor(url);
          const bm = createBypassManager([matchingPattern]);

          // Before removal: must match
          if (bm.shouldBypass(url) !== true) return false;

          // After removal: must not match
          bm.removeRule(matchingPattern);
          return bm.shouldBypass(url) === false;
        },
      ),
      { numRuns: 500 },
    );
  });
});
