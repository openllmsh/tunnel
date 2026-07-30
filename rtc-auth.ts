/**
 * Pure RTC fingerprint-binding helpers for the browser⇄daemon data channel.
 *
 * Trust root: the daemon's long-lived X25519 public key (published on
 * DaemonStatus, pinned by the browser via the cloud status path). The relay
 * only carries SDP + sealed proofs and must not be able to MITM DTLS.
 *
 * Protocol (sealed-box challenge/response, no new crypto primitives):
 *   1. Browser mints nonce N (16B), reads its DTLS fingerprint Fb, generates
 *      an ephemeral X25519 keypair, and seals
 *        { v:1, n, fb, epk }
 *      to the daemon pubkey. That ciphertext is `fingerprint_proof` on
 *      `rtc_offer` (alongside the SDP offer).
 *   2. Daemon opens the seal with its private key, checks shape, then seals
 *        { v:1, n, fb, fd }
 *      to the browser's ephemeral pubkey. That ciphertext is
 *      `fingerprint_proof` on `rtc_answer`.
 *   3. Browser opens the answer seal, checks N matches (replay), Fb matches
 *      its local fingerprint, and Fd matches the fingerprint in the answer
 *      SDP — only then completes DTLS / marks the channel open.
 *
 * This module is dependency-free: hosts supply seal/open via the existing
 * sealed-box implementations (`lib/daemon-seal.ts` / `packages/daemon/src/
 * keypair.ts`). Fingerprint strings are normalized (lowercase, strip
 * separators) so SDP `a=fingerprint:sha-256 AA:BB:…` and bare hex compare
 * equal.
 */

export const RTC_AUTH_VERSION = 1 as const;
/** 16 random bytes, base64-encoded in the inner JSON. */
export const RTC_AUTH_NONCE_BYTES = 16;
/**
 * Floor for the negotiated mux DATA payload under SCTP. Matches the plan's
 * "safe floor if SDP omits max-message-size".
 */
export const RTC_SAFE_MAX_PAYLOAD_BYTES = 16 * 1024;
/** Header bytes reserved so a mux frame fits inside an SCTP message. */
export const RTC_MUX_HEADER_OVERHEAD = 9;

export type TRtcOfferInner = {
  readonly v: typeof RTC_AUTH_VERSION;
  /** base64 of RTC_AUTH_NONCE_BYTES random bytes */
  readonly n: string;
  /** browser DTLS fingerprint, already normalized */
  readonly fb: string;
  /** browser ephemeral X25519 public key (SPKI DER, base64) for the answer seal */
  readonly epk: string;
};

export type TRtcAnswerInner = {
  readonly v: typeof RTC_AUTH_VERSION;
  readonly n: string;
  /** echo of the browser fingerprint (normalized) */
  readonly fb: string;
  /** daemon DTLS fingerprint (normalized) */
  readonly fd: string;
};

/** Strip algorithm prefix + separators; lowercase. Empty input → "". */
export const normalizeFingerprint = (raw: string): string => {
  const trimmed = raw.trim();
  // SDP form: "sha-256 AA:BB:..." or just "AA:BB:..."
  const withoutAlgo = trimmed.includes(" ")
    ? (trimmed.split(/\s+/).pop() ?? "")
    : trimmed;
  return withoutAlgo.replace(/:/g, "").toLowerCase();
};

/**
 * Extract `a=fingerprint:` value from an SDP blob. Returns the raw value
 * (algorithm + hex) or null if absent. Caller normalizes for comparison.
 */
export const fingerprintFromSdp = (sdp: string): string | null => {
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:(.+)$/i.exec(line.trim());
    if (m !== null) return m[1].trim();
  }
  return null;
};

/**
 * Extract SCTP `a=max-message-size:` from SDP. Returns null if absent or
 * unparseable. Some browsers omit it (then use {@link RTC_SAFE_MAX_PAYLOAD_BYTES}).
 */
export const maxMessageSizeFromSdp = (sdp: string): number | null => {
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=max-message-size:(\d+)$/i.exec(line.trim());
    if (m !== null) {
      const n = Number(m[1]);
      if (Number.isFinite(n) && n > 0) return n;
    }
  }
  return null;
};

/**
 * Mux DATA payload cap for an RTC channel: min(SDP max-message-size − header,
 * MAX_PAYLOAD_BYTES) with a safe floor when SDP omits the attribute.
 * `wireMax` is typically {@link MAX_PAYLOAD_BYTES} from the codec.
 *
 * Returns `null` when the advertised SCTP limit cannot fit even a 1-byte DATA
 * frame (limit ≤ header overhead) — callers must abort session setup rather
 * than mount a mux that can never drain.
 */
export const negotiateRtcPayloadCap = (
  sdpMaxMessageSize: number | null,
  wireMax: number,
): number | null => {
  if (sdpMaxMessageSize === null) {
    return Math.min(RTC_SAFE_MAX_PAYLOAD_BYTES, wireMax);
  }
  const usable = sdpMaxMessageSize - RTC_MUX_HEADER_OVERHEAD;
  if (usable < 1) return null;
  if (usable < RTC_SAFE_MAX_PAYLOAD_BYTES) {
    // Pathological-but-usable SDP — still try whatever fits.
    return Math.min(usable, wireMax);
  }
  return Math.min(usable, wireMax);
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

export const encodeOfferInner = (inner: TRtcOfferInner): string =>
  JSON.stringify({
    v: RTC_AUTH_VERSION,
    n: inner.n,
    fb: normalizeFingerprint(inner.fb),
    epk: inner.epk,
  });

export const decodeOfferInner = (json: string): TRtcOfferInner | null => {
  try {
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object") return null;
    const o = parsed as Record<string, unknown>;
    if (o.v !== RTC_AUTH_VERSION) return null;
    if (
      !isNonEmptyString(o.n) ||
      !isNonEmptyString(o.fb) ||
      !isNonEmptyString(o.epk)
    ) {
      return null;
    }
    return {
      v: RTC_AUTH_VERSION,
      n: o.n,
      fb: normalizeFingerprint(o.fb),
      epk: o.epk,
    };
  } catch {
    return null;
  }
};

export const encodeAnswerInner = (inner: TRtcAnswerInner): string =>
  JSON.stringify({
    v: RTC_AUTH_VERSION,
    n: inner.n,
    fb: normalizeFingerprint(inner.fb),
    fd: normalizeFingerprint(inner.fd),
  });

export const decodeAnswerInner = (json: string): TRtcAnswerInner | null => {
  try {
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object") return null;
    const o = parsed as Record<string, unknown>;
    if (o.v !== RTC_AUTH_VERSION) return null;
    if (
      !isNonEmptyString(o.n) ||
      !isNonEmptyString(o.fb) ||
      !isNonEmptyString(o.fd)
    ) {
      return null;
    }
    return {
      v: RTC_AUTH_VERSION,
      n: o.n,
      fb: normalizeFingerprint(o.fb),
      fd: normalizeFingerprint(o.fd),
    };
  } catch {
    return null;
  }
};

/**
 * Browser-side check of a decoded answer against the offer it sent and the
 * fingerprints observed in local/remote SDP.
 */
export const verifyAnswerInner = (
  answer: TRtcAnswerInner,
  expected: {
    readonly nonce: string;
    readonly browserFingerprint: string;
    readonly daemonFingerprint: string;
  },
): boolean =>
  answer.n === expected.nonce &&
  answer.fb === normalizeFingerprint(expected.browserFingerprint) &&
  answer.fd === normalizeFingerprint(expected.daemonFingerprint);
