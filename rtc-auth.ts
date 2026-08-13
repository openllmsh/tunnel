/**
 * Pure RTC fingerprint-binding helpers for the browser⇄daemon data channel.
 *
 * Trust root: the daemon's long-lived X25519 public key (published on
 * DaemonStatus, pinned by the browser via the cloud status path). The relay
 * only carries SDP + sealed proofs and must not be able to MITM DTLS.
 *
 * Protocol (sealed-box challenge/response, no new crypto primitives):
 *   1. Browser mints nonce N (16B), reads its DTLS fingerprint Fb, generates
 *      an ephemeral X25519 keypair, and seals the offer inner to the daemon
 *      pubkey. That ciphertext is `fingerprint_proof` on `rtc_offer`
 *      (alongside the SDP offer).
 *   2. Daemon opens the seal with its private key, checks shape, then seals
 *        { v:1, n, fb, fd }
 *      to the browser's ephemeral pubkey. That ciphertext is
 *      `fingerprint_proof` on `rtc_answer`.
 *   3. Browser opens the answer seal, checks N matches (replay), Fb matches
 *      its local fingerprint, and Fd matches the fingerprint in the answer
 *      SDP — only then completes DTLS / marks the channel open.
 *
 * Offer-inner versions:
 *   - v1 `{v:1, n, fb, epk}` — legacy, accepted only when the daemon is
 *     un-provisioned for seed-gated device access.
 *   - v2 `{v:2, n, fb, epk, grant}` — nested full device-grant envelope
 *     (base64 from `encodeDeviceGrant`). Reuses standard grant validation
 *     (ts window, nonce, key_id, cid, aud, sig); the sealed box already
 *     binds fb/epk so the grant itself stays the plain device-grant shape
 *     with `cid=channel_id` and `aud=daemon_pubkey`.
 *
 * Hosts supply seal/open via the existing sealed-box implementations
 * (`lib/daemon-seal.ts` / `packages/daemon/src/keypair.ts`). Fingerprint
 * strings are normalized (lowercase, strip separators) so SDP
 * `a=fingerprint:sha-256 AA:BB:…` and bare hex compare equal.
 */

import type { TIceServer } from "@openllmsh/protocol";
import { FRAME_HEADER_BYTES } from "./codec";

export const RTC_AUTH_VERSION = 1 as const;
/** Default STUN server shared by browser and daemon RTC peers. */
export const RTC_DEFAULT_STUN = "stun:stun.l.google.com:19302";

/**
 * Default STUN fallback list for STUN-only sessions.
 *
 * Keep multiple independent providers here so a single provider failure does not
 * zero out server-reflexive candidates. This is a resilience improvement for
 * provider diversity, but it does not replace TURN for fully UDP-blocked
 * networks.
 */
export const RTC_DEFAULT_STUN_SERVERS: ReadonlyArray<string> = [
  RTC_DEFAULT_STUN,
  "stun:stun1.l.google.com:19302",
  "stun:stun.cloudflare.com:3478",
];

/** Return a fresh default ICE configuration for callers that need STUN-only. */
export const defaultIceServers = (): ReadonlyArray<TIceServer> =>
  RTC_DEFAULT_STUN_SERVERS.map((url) => ({ urls: url }));

/** Map immutable protocol ICE entries into werift's mutable input shape. */
export const weriftIceServers = (
  servers: ReadonlyArray<TIceServer>,
): Array<{
  urls: string | string[];
  username?: string;
  credential?: string;
}> =>
  servers.map((server) => ({
    urls: typeof server.urls === "string" ? server.urls : [...server.urls],
    ...(server.username !== undefined ? { username: server.username } : {}),
    ...(server.credential !== undefined
      ? { credential: server.credential }
      : {}),
  }));

const isIceUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return ["stun:", "stuns:", "turn:", "turns:"].includes(url.protocol);
  } catch {
    return false;
  }
};

const iceUrls = (value: unknown): string | string[] | null => {
  if (typeof value === "string") {
    const url = value.trim();
    return isIceUrl(url) ? url : null;
  }
  if (!Array.isArray(value)) return null;
  const urls = value
    .filter((url): url is string => typeof url === "string")
    .map((url) => url.trim())
    .filter(isIceUrl);
  return urls.length > 0 ? urls : null;
};

/** Parse an ICE-server configuration string into RTCPeerConnection entries.
 *
 *  Accepts, in order of precedence of the input shape:
 *    - undefined / empty → the default Google STUN entry;
 *    - a JSON array of ice-server objects
 *      (`[{urls, username?, credential?}, …]` — the TURN-ready form served by
 *      the cloud via the `/api/daemon/channel` handshake and set directly via
 *      `OPENLLM_RTC_ICE_SERVERS`);
 *    - a legacy comma-separated STUN URL list (the historical
 *      `OPENLLM_RTC_STUN` form).
 *
 *  Malformed input (bad JSON, wrong shape, no usable urls) falls back to the
 *  default so a config typo degrades to STUN-only instead of killing RTC. */
export const parseIceServers = (
  raw: string | undefined,
): ReadonlyArray<TIceServer> => {
  const trimmed = raw?.trim();
  if (trimmed === undefined || trimmed.length === 0) return defaultIceServers();
  if (trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        const servers: TIceServer[] = [];
        for (const entry of parsed) {
          if (entry === null || typeof entry !== "object") continue;
          const record = entry as Record<string, unknown>;
          const urls = iceUrls(record.urls);
          if (urls === null) continue;
          const username =
            typeof record.username === "string" &&
            record.username.trim().length > 0
              ? record.username.trim()
              : undefined;
          const credential =
            typeof record.credential === "string" &&
            record.credential.trim().length > 0
              ? record.credential.trim()
              : undefined;
          servers.push({
            urls,
            ...(username !== undefined ? { username } : {}),
            ...(credential !== undefined ? { credential } : {}),
          });
        }
        if (servers.length > 0) return servers;
      }
    } catch {
      // fall through to the default — a malformed JSON list must not kill RTC
    }
    return defaultIceServers();
  }
  const legacy = trimmed
    .split(",")
    .map((value) => value.trim())
    .filter(isIceUrl)
    .map((urls) => ({ urls }));
  return legacy.length > 0 ? legacy : defaultIceServers();
};

/** Resolve the effective ICE servers for an RTC peer, in precedence order:
 *    1. a locally-set env value (`OPENLLM_RTC_ICE_SERVERS`, or the legacy
 *       `OPENLLM_RTC_STUN` STUN list) — parsed via {@link parseIceServers};
 *    2. the cloud-served `ice_servers` from the channel handshake;
 *    3. the default STUN entry.
 *  Shared by both daemon RTC ends so browser/daemon agree on the surface. */
export const resolveIceServers = (
  envRaw: string | undefined,
  handshake: ReadonlyArray<TIceServer> | null,
): ReadonlyArray<TIceServer> => {
  const trimmed = envRaw?.trim();
  if (trimmed !== undefined && trimmed.length > 0) {
    return parseIceServers(trimmed);
  }
  if (handshake !== null && handshake.length > 0) return handshake;
  return defaultIceServers();
};

/** Seed-gated offer inner: nests a full device-grant envelope. */
export const RTC_AUTH_VERSION_2 = 2 as const;
/** 16 random bytes, base64-encoded in the inner JSON. */
export const RTC_AUTH_NONCE_BYTES = 16;
/**
 * Floor for the negotiated mux DATA payload under SCTP. Matches the plan's
 * "safe floor if SDP omits max-message-size".
 */
export const RTC_SAFE_MAX_PAYLOAD_BYTES = 16 * 1024;
/** Header bytes reserved so a mux frame fits inside an SCTP message. */
export const RTC_MUX_HEADER_OVERHEAD = FRAME_HEADER_BYTES;

export type TRtcOfferInnerV1 = {
  readonly v: typeof RTC_AUTH_VERSION;
  /** base64 of RTC_AUTH_NONCE_BYTES random bytes */
  readonly n: string;
  /** browser DTLS fingerprint, already normalized */
  readonly fb: string;
  /** browser ephemeral X25519 public key (SPKI DER, base64) for the answer seal */
  readonly epk: string;
};

/**
 * v2 offer inner. `grant` is the full `encodeDeviceGrant(...)` envelope
 * string (base64 JSON). Nested rather than flat sig fields so the daemon
 * reuses `checkDeviceGrant` (ts window, nonce LRU, key_id/cid/aud/sig)
 * without a parallel validation path.
 */
export type TRtcOfferInnerV2 = {
  readonly v: typeof RTC_AUTH_VERSION_2;
  readonly n: string;
  readonly fb: string;
  readonly epk: string;
  /** Full device-grant envelope (base64). */
  readonly grant: string;
};

export type TRtcOfferInner = TRtcOfferInnerV1 | TRtcOfferInnerV2;

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
 * Extract effective DTLS fingerprints from an SDP blob.
 *
 * Returns all `a=fingerprint:` lines from the first `m=application` section that has
 * fingerprints; otherwise returns session-level fingerprints (before any `m=`). The
 * values are raw (algorithm + hex) and preserve order.
 */
export const fingerprintsFromSdp = (sdp: string): readonly string[] => {
  const sessionFingerprints: string[] = [];
  let applicationFingerprints: string[] | null = null;
  let inApplicationSection = false;
  let hasMediaSection = false;

  for (const line of sdp.split(/\r?\n/)) {
    const trimmed = line.trim();
    const media = /^m=([^\s]+)/i.exec(trimmed);
    if (media !== null) {
      hasMediaSection = true;
      inApplicationSection = media[1].toLowerCase() === "application";
      if (inApplicationSection && applicationFingerprints === null) {
        applicationFingerprints = [];
      }
      continue;
    }

    const match = /^a=fingerprint:(.+)$/i.exec(trimmed);
    if (match === null) continue;
    if (inApplicationSection) {
      applicationFingerprints?.push(match[1].trim());
      continue;
    }
    if (!hasMediaSection) {
      sessionFingerprints.push(match[1].trim());
    }
  }

  return applicationFingerprints !== null && applicationFingerprints.length > 0
    ? applicationFingerprints
    : sessionFingerprints;
};

/**
 * True when the effective SDP fingerprint set is non-empty and every entry
 * matches the sealed/claimed fingerprint after normalization. Conflicting
 * fingerprint lines are rejected rather than accepting a matching subset.
 */
export const sdpFingerprintsMatch = (
  sdp: string,
  claimedFingerprint: string,
): boolean => {
  const claimed = normalizeFingerprint(claimedFingerprint);
  const fingerprints = fingerprintsFromSdp(sdp);
  return (
    claimed.length > 0 &&
    fingerprints.length > 0 &&
    fingerprints.every(
      (fingerprint) => normalizeFingerprint(fingerprint) === claimed,
    )
  );
};

/**
 * Extract `a=fingerprint:` value from an SDP blob. Returns the first raw value from
 * the effective set (session-level or `m=application`) or null if absent. Caller
 * normalizes for comparison.
 */
export const fingerprintFromSdp = (sdp: string): string | null => {
  const fingerprints = fingerprintsFromSdp(sdp);
  return fingerprints.length > 0 ? fingerprints[0] : null;
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
  return Math.min(usable, wireMax);
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** True when a nonce is base64 of exactly RTC_AUTH_NONCE_BYTES bytes. */
const isValidNonce = (value: unknown): value is string => {
  if (!isNonEmptyString(value)) return false;
  try {
    return atob(value).length === RTC_AUTH_NONCE_BYTES;
  } catch {
    return false;
  }
};

export const encodeOfferInner = (inner: TRtcOfferInner): string => {
  if (inner.v === RTC_AUTH_VERSION_2) {
    return JSON.stringify({
      v: RTC_AUTH_VERSION_2,
      n: inner.n,
      fb: normalizeFingerprint(inner.fb),
      epk: inner.epk,
      grant: inner.grant,
    });
  }
  return JSON.stringify({
    v: RTC_AUTH_VERSION,
    n: inner.n,
    fb: normalizeFingerprint(inner.fb),
    epk: inner.epk,
  });
};

export const decodeOfferInner = (json: string): TRtcOfferInner | null => {
  try {
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object") return null;
    const o = parsed as Record<string, unknown>;
    if (
      !isValidNonce(o.n) ||
      !isNonEmptyString(o.fb) ||
      !isNonEmptyString(o.epk)
    ) {
      return null;
    }
    if (o.v === RTC_AUTH_VERSION_2) {
      if (!isNonEmptyString(o.grant)) return null;
      return {
        v: RTC_AUTH_VERSION_2,
        n: o.n,
        fb: normalizeFingerprint(o.fb),
        epk: o.epk,
        grant: o.grant,
      };
    }
    if (o.v !== RTC_AUTH_VERSION) return null;
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
