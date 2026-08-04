/**
 * ICE candidate preflight for the daemon's werift peers.
 *
 * Browsers trickle mDNS `.local` host candidates (RFC 8445 §4.1 privacy
 * obfuscation). werift's `addIceCandidate` handles them by issuing a REAL
 * multicast-DNS query per candidate (`MdnsLookup` in @werift/ice) with a
 * fixed 10-second timeout, and drops the candidate when resolution fails.
 * On-LAN that resolves in milliseconds; OFF-LAN (the cross-network case)
 * nothing ever answers, so EVERY `.local` candidate costs a serialized
 * 10-second stall inside the peer connection before werift moves on. With a
 * typical browser offering several mDNS candidates, that is tens of seconds
 * of ICE silence — past the offerer's ICE timeout — and shows up as the
 * `handshake_timeout` session closes the daemon logs.
 *
 * werift's own timeout is not configurable, so the daemon preflights `.local`
 * candidates itself: one short `dns.lookup` (mDNS-aware on macOS and on
 * Linux hosts with a working NSS mDNS plugin) decides LAN-ness once; when
 * the name does not resolve quickly, this and every later `.local`
 * candidate is skipped IMMEDIATELY instead of feeding werift another 10 s
 * probe. The verdict is cached process-wide because LAN-ness does not change
 * between candidates of one connection.
 *
 * Non-`.local` candidates are never touched.
 */

const MDNS_PREFLIGHT_TIMEOUT_MS = 250;

/** Cached preflight verdict: true = `.local` resolved quickly (LAN) → keep
 *  feeding candidates to werift; false = skip them fast. */
let mdnsVerdict: boolean | null = null;
let mdnsPreflightInFlight: Promise<boolean> | null = null;

/** True when the candidate init carries an mDNS `.local` host name. */
export const isMdnsCandidate = (init: {
  readonly candidate?: string | null;
}): boolean =>
  typeof init.candidate === "string" && init.candidate.includes(".local");

const lookupOnce = async (host: string): Promise<boolean> => {
  const { lookup } = await import("node:dns/promises");
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), MDNS_PREFLIGHT_TIMEOUT_MS);
    lookup(host)
      .then(() => {
        clearTimeout(timer);
        resolve(true);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(false);
      });
  });
};

/**
 * Preflight an ICE candidate before handing it to werift. Returns true when
 * the candidate should be applied. `.local` candidates consult (and cache)
 * the one-shot LAN verdict; the preflight uses the candidate's own host name
 * so a resolved name ALSO primes the OS resolver cache for werift's own
 * lookup that follows.
 */
export const preflightIceCandidate = async (init: {
  readonly candidate?: string | null;
}): Promise<boolean> => {
  const candidate = init.candidate;
  if (typeof candidate !== "string") return true;
  const match = / ([a-z0-9-]+\.local) /i.exec(candidate);
  if (match === null) return true;
  if (mdnsVerdict !== null) return mdnsVerdict;
  if (mdnsPreflightInFlight === null) {
    mdnsPreflightInFlight = lookupOnce(match[1])
      .then((ok) => {
        mdnsVerdict = ok;
        return ok;
      })
      .finally(() => {
        mdnsPreflightInFlight = null;
      });
  }
  return mdnsPreflightInFlight;
};

/** Test-only: clear the cached LAN verdict between cases. */
export const resetMdnsPreflightForTest = (): void => {
  mdnsVerdict = null;
  mdnsPreflightInFlight = null;
};
