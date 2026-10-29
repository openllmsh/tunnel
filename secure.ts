/**
 * Noise_IK end-to-end encryption for traffic that crosses the blind relay.
 *
 * Why: on the relay mux fallback (RTC unavailable or forced off) every byte
 * of an agent stream passes through the relay. RTC is already E2E (DTLS bound
 * to the daemon key in `rtc-auth.ts`); this module gives the relay rung the
 * same property, so the relay forwards ciphertext only.
 *
 * Pattern: `Noise_IK_25519_AESGCM_SHA256` (Noise spec rev 34), built only on
 * WebCrypto (X25519, HMAC-SHA-256, AES-256-GCM). The package keeps no crypto
 * dependency and runs unchanged in browsers, Bun and Node.
 *
 *   IK:
 *     <- s                       responder static = the daemon's X25519 key
 *     ...                        (`dpk`, verified by the caller — dpk proof
 *                                 or control attestation)
 *     -> e, es, s, ss            payload: host-defined (a device grant)
 *     <- e, ee, se               payload: host-defined (may be empty)
 *
 * The initiator (browser) must already know the daemon static key: a relay
 * that swaps keys cannot read message 1 or answer it, so the handshake fails
 * closed. The initiator's own static key may be per-session; it is
 * authenticated by the device grant carried in the message-1 payload, which
 * the responder checks in `authorize` (including the grant's `dpk`).
 *
 * Two carriers share one handshake core:
 *   - {@link secureDuplex} wraps a message-oriented {@link TDuplex}. Each
 *     Noise message is one duplex message; a plaintext larger than one Noise
 *     message is split into records with a continuation flag and reassembled
 *     (bounded by `maxMessageBytes`).
 *   - {@link secureMuxStream} wraps one {@link TMuxStream} (the agent path).
 *     DATA is a byte stream, so each Noise message is framed with the Noise
 *     spec's 2-byte big-endian length prefix. Stream CTRL payloads are
 *     encrypted too, under a second key pair derived from the final chaining
 *     key (`HKDF(ck, "openllm-secure-ctrl-v1")`) — CTRL and DATA may leave the
 *     mux in a different order than they were written (DATA waits for flow
 *     credit), so each needs its own nonce counter. RESET payloads, END and
 *     WINDOW stay plaintext: they carry reset codes and flow control the relay
 *     and both peers must read, never session content.
 *
 * Deviation from the spec, deliberate and documented: the CTRL key pair above
 * is an extra output of the final chaining key. It does not change the Noise
 * handshake or the DATA transport keys from `Split()`.
 */
import type { TStreamResetCode } from "@openllmsh/protocol";
import { encodeJsonPayload } from "./codec";
import type { TDuplex, TMuxEventHandler, TMuxStream } from "./mux";

export const NOISE_PROTOCOL_NAME = "Noise_IK_25519_AESGCM_SHA256";
export const NOISE_PSK_PROTOCOL_NAME = "Noise_IKpsk2_25519_AESGCM_SHA256";
export const NOISE_DH_LEN = 32;
export const NOISE_TAG_LEN = 16;
/** Noise spec limit on one handshake or transport message. */
export const NOISE_MAX_MESSAGE_BYTES = 65_535;
/** Default prologue; hosts should bind the channel / stream id via `prologue`. */
export const SECURE_DEFAULT_PROLOGUE = "openllm-secure-v1";
export const SECURE_HANDSHAKE_TIMEOUT_MS = 15_000;
/** {@link secureDuplex} reassembly cap for one plaintext message. */
export const SECURE_DUPLEX_MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
/** Cap on a handshake payload (a device grant fits easily). */
export const SECURE_MAX_HANDSHAKE_PAYLOAD_BYTES = 16 * 1024;

const CTRL_KEY_INFO = "openllm-secure-ctrl-v1";
/** CTRL frames held while the local side finishes the handshake. */
const SECURE_MAX_EARLY_CTRL = 64;
/** Messages / records held while the local side finishes the handshake. */
const SECURE_MAX_EARLY_MESSAGES = 64;
/** Plaintext per stream record (one Noise transport message). */
const STREAM_RECORD_PLAINTEXT = NOISE_MAX_MESSAGE_BYTES - NOISE_TAG_LEN;
/** Plaintext per duplex record: one byte is the continuation flag. */
const DUPLEX_RECORD_PLAINTEXT = STREAM_RECORD_PLAINTEXT - 1;
const RECORD_MORE = 0x01;
const RECORD_FINAL = 0x00;
const LENGTH_PREFIX_BYTES = 2;
/** DER prefix of an X25519 SubjectPublicKeyInfo (RFC 8410). */
const X25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

export type TSecureErrorCode =
  /** AEAD failed: wrong responder key, tampering, or replay. */
  | "decrypt_failed"
  /** Bytes do not parse as a Noise message. */
  | "malformed"
  /** The responder's `authorize` refused the initiator. */
  | "refused"
  | "timeout"
  /** The carrier closed or reset before the handshake finished. */
  | "closed";

export class SecureChannelError extends Error {
  readonly code: TSecureErrorCode;
  constructor(code: TSecureErrorCode, message: string) {
    super(message);
    this.name = "SecureChannelError";
    this.code = code;
  }
}

/**
 * A static X25519 identity. `dh` keeps the private key with its owner, so a
 * daemon can back it with its node:crypto `KeyObject` without exporting it.
 */
export type TNoiseStaticKey = {
  /** Raw 32-byte X25519 public key. */
  readonly publicKey: Uint8Array;
  /** X25519(private, remotePublic) → 32-byte shared secret. */
  readonly dh: (remotePublic: Uint8Array) => Promise<Uint8Array>;
};

export type TSecureAuthorizeContext = {
  /** The initiator's raw 32-byte static key (authenticated by Noise). */
  readonly remoteStatic: Uint8Array;
  /** The initiator's message-1 payload (e.g. a device grant). */
  readonly payload: Uint8Array;
};

type TSecureCommonOptions = {
  /** Bound into the handshake hash; both sides must agree. */
  readonly prologue?: Uint8Array;
  /** Optional 32-byte pre-shared key; selects Noise IKpsk2. */
  readonly psk?: Uint8Array;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
};

export type TSecureInitiatorOptions = TSecureCommonOptions & {
  readonly role: "initiator";
  /** The responder's static key (`dpk`): raw 32 bytes or SPKI DER base64. */
  readonly remoteStatic: Uint8Array | string;
  /** Defaults to a fresh per-session key. */
  readonly localStatic?: TNoiseStaticKey;
  /** Message-1 payload, encrypted to the responder (e.g. a device grant). */
  readonly payload?: Uint8Array;
};

export type TSecureResponderOptions = TSecureCommonOptions & {
  readonly role: "responder";
  readonly localStatic: TNoiseStaticKey;
  /**
   * Admit or refuse the initiator after message 1 decrypts. Return the
   * message-2 payload (may be empty) to admit, or `null` to refuse. Throwing
   * also refuses.
   */
  readonly authorize: (
    context: TSecureAuthorizeContext,
  ) => Uint8Array | null | Promise<Uint8Array | null>;
};

export type TSecureOptions = TSecureInitiatorOptions | TSecureResponderOptions;

export type TSecureSession = {
  /** The peer's raw 32-byte static key. */
  readonly remoteStatic: Uint8Array;
  /** The peer's handshake payload. */
  readonly peerPayload: Uint8Array;
  /** Final handshake hash `h` — a channel-binding value. */
  readonly handshakeHash: Uint8Array;
};

export type TSecureDuplex = TDuplex & TSecureSession;
type TSecurePhase = "handshake" | "open" | "dead";
export type TSecureMuxStream = TMuxStream & TSecureSession;

// ---------------------------------------------------------------------------
// Bytes + key helpers
// ---------------------------------------------------------------------------

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

/** Copy into a fresh ArrayBuffer-backed view (what WebCrypto accepts). */
const own = (bytes: Uint8Array): Uint8Array<ArrayBuffer> =>
  new Uint8Array(bytes);

const concatBytes = (...parts: ReadonlyArray<Uint8Array>): Uint8Array => {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
};

const isAllZero = (bytes: Uint8Array): boolean => {
  let acc = 0;
  for (const byte of bytes) acc |= byte;
  return acc === 0;
};

const base64ToBytes = (b64: string): Uint8Array | null => {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
};

/**
 * Raw 32-byte X25519 key from SPKI DER base64 (the `DaemonStatus.pubkey` /
 * `dpk` format). Null when it is not an X25519 SPKI.
 */
export const x25519RawFromSpkiB64 = (spkiB64: string): Uint8Array | null => {
  const der = base64ToBytes(spkiB64);
  if (der === null) return null;
  if (der.byteLength !== X25519_SPKI_PREFIX.byteLength + NOISE_DH_LEN) {
    return null;
  }
  if (
    !bytesEqual(
      der.subarray(0, X25519_SPKI_PREFIX.byteLength),
      X25519_SPKI_PREFIX,
    )
  ) {
    return null;
  }
  return der.slice(X25519_SPKI_PREFIX.byteLength);
};

/** SPKI DER base64 for a raw 32-byte X25519 key. */
export const x25519SpkiB64FromRaw = (raw: Uint8Array): string => {
  if (raw.byteLength !== NOISE_DH_LEN) {
    throw new RangeError("X25519 public key must be 32 bytes");
  }
  return bytesToBase64(concatBytes(X25519_SPKI_PREFIX, raw));
};

const resolveRemoteStatic = (value: Uint8Array | string): Uint8Array => {
  const raw = typeof value === "string" ? x25519RawFromSpkiB64(value) : value;
  if (raw === null || raw.byteLength !== NOISE_DH_LEN) {
    throw new SecureChannelError(
      "malformed",
      "responder static key is not an X25519 key",
    );
  }
  return raw;
};

const x25519 = async (
  privateKey: CryptoKey,
  remotePublic: Uint8Array,
): Promise<Uint8Array> => {
  let shared: Uint8Array;
  try {
    const publicKey = await subtle().importKey(
      "raw",
      own(remotePublic),
      { name: "X25519" },
      false,
      [],
    );
    shared = new Uint8Array(
      await subtle().deriveBits(
        { name: "X25519", public: publicKey },
        privateKey,
        NOISE_DH_LEN * 8,
      ),
    );
  } catch {
    throw new SecureChannelError("malformed", "invalid X25519 public key");
  }
  // A low-order point yields an all-zero secret; never key from it.
  if (isAllZero(shared)) {
    throw new SecureChannelError("malformed", "invalid X25519 public key");
  }
  return shared;
};

/** A {@link TNoiseStaticKey} backed by a WebCrypto X25519 key pair. */
export const noiseStaticKeyFromCryptoKeyPair = async (
  pair: CryptoKeyPair,
): Promise<TNoiseStaticKey> => {
  const publicKey = new Uint8Array(
    await subtle().exportKey("raw", pair.publicKey),
  );
  return {
    publicKey,
    dh: (remotePublic) => x25519(pair.privateKey, remotePublic),
  };
};

/** Mint a fresh WebCrypto X25519 static (or ephemeral) key. */
export const generateNoiseStaticKey = async (): Promise<TNoiseStaticKey> => {
  const pair = (await subtle().generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  return noiseStaticKeyFromCryptoKeyPair(pair);
};

// ---------------------------------------------------------------------------
// Noise symmetric state (spec §5.1–5.2)
// ---------------------------------------------------------------------------

type TCipherState = {
  key: CryptoKey | null;
  nonce: number;
};

const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await subtle().digest("SHA-256", own(data)));

const hmac = async (key: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const k = await subtle().importKey(
    "raw",
    own(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle().sign("HMAC", k, own(data)));
};

/** Derive the team-specific Noise PSK from the team key. */
export const deriveTeamTunnelPsk = async (
  teamKey: Uint8Array,
  teamId: string,
): Promise<Uint8Array> => {
  const key = await subtle().importKey("raw", own(teamKey), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await subtle().deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: own(new TextEncoder().encode(teamId)),
        info: own(new TextEncoder().encode("openllm-team-tunnel-psk-v1")),
      },
      key,
      256,
    ),
  );
};

/** Noise HKDF with two outputs. */
const hkdf2 = async (
  chainingKey: Uint8Array,
  ikm: Uint8Array,
): Promise<readonly [Uint8Array, Uint8Array]> => {
  const temp = await hmac(chainingKey, ikm);
  const out1 = await hmac(temp, new Uint8Array([0x01]));
  const out2 = await hmac(temp, concatBytes(out1, new Uint8Array([0x02])));
  return [out1, out2];
};

const aesKey = (raw: Uint8Array): Promise<CryptoKey> =>
  subtle().importKey("raw", own(raw), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);

/** Noise AESGCM nonce: 32 zero bits then the 64-bit big-endian counter. */
const gcmNonce = (counter: number): Uint8Array<ArrayBuffer> => {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, BigInt(counter), false);
  return iv;
};

const cipherState = (key: CryptoKey | null): TCipherState => ({
  key,
  nonce: 0,
});

/** Claim the next nonce synchronously so concurrent callers never reuse one. */
const nextNonce = (cs: TCipherState): number => {
  if (cs.nonce >= Number.MAX_SAFE_INTEGER) {
    throw new SecureChannelError("closed", "nonce space exhausted");
  }
  const n = cs.nonce;
  cs.nonce += 1;
  return n;
};

const encryptWithAd = async (
  cs: TCipherState,
  ad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> => {
  if (cs.key === null) return plaintext;
  const n = nextNonce(cs);
  return new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv: gcmNonce(n), additionalData: own(ad) },
      cs.key,
      own(plaintext),
    ),
  );
};

const decryptWithAd = async (
  cs: TCipherState,
  ad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> => {
  if (cs.key === null) return ciphertext;
  if (ciphertext.byteLength < NOISE_TAG_LEN) {
    throw new SecureChannelError("malformed", "ciphertext shorter than a tag");
  }
  const n = nextNonce(cs);
  try {
    return new Uint8Array(
      await subtle().decrypt(
        { name: "AES-GCM", iv: gcmNonce(n), additionalData: own(ad) },
        cs.key,
        own(ciphertext),
      ),
    );
  } catch {
    throw new SecureChannelError("decrypt_failed", "authentication failed");
  }
};

type TSymmetricState = {
  ck: Uint8Array;
  h: Uint8Array;
  cs: TCipherState;
};

const initSymmetric = async (
  prologue: Uint8Array,
  psk?: Uint8Array,
): Promise<TSymmetricState> => {
  if (psk !== undefined && psk.byteLength !== 32) {
    throw new SecureChannelError("malformed", "Noise PSK must be 32 bytes");
  }
  const name = new TextEncoder().encode(
    psk === undefined ? NOISE_PROTOCOL_NAME : NOISE_PSK_PROTOCOL_NAME,
  );
  const h = new Uint8Array(32);
  if (name.byteLength <= 32) h.set(name);
  else h.set(await sha256(name));
  const state: TSymmetricState = { ck: h.slice(), h, cs: cipherState(null) };
  await mixHash(state, prologue);
  return state;
};

const mixHash = async (
  state: TSymmetricState,
  data: Uint8Array,
): Promise<void> => {
  state.h = await sha256(concatBytes(state.h, data));
};

const mixKey = async (
  state: TSymmetricState,
  ikm: Uint8Array,
): Promise<void> => {
  const [ck, tempK] = await hkdf2(state.ck, ikm);
  state.ck = ck;
  state.cs = cipherState(await aesKey(tempK));
};

const mixKeyAndHash = async (
  state: TSymmetricState,
  psk: Uint8Array,
): Promise<void> => {
  const temp = await hmac(state.ck, psk);
  const ck = await hmac(temp, new Uint8Array([1]));
  const tempH = await hmac(temp, concatBytes(ck, new Uint8Array([2])));
  const tempK = await hmac(temp, concatBytes(tempH, new Uint8Array([3])));
  state.ck = ck;
  await mixHash(state, tempH);
  state.cs = cipherState(await aesKey(tempK));
};

const encryptAndHash = async (
  state: TSymmetricState,
  plaintext: Uint8Array,
): Promise<Uint8Array> => {
  const ciphertext = await encryptWithAd(state.cs, state.h, plaintext);
  await mixHash(state, ciphertext);
  return ciphertext;
};

const decryptAndHash = async (
  state: TSymmetricState,
  ciphertext: Uint8Array,
): Promise<Uint8Array> => {
  const plaintext = await decryptWithAd(state.cs, state.h, ciphertext);
  await mixHash(state, ciphertext);
  return plaintext;
};

type TTransportKeys = {
  readonly send: TCipherState;
  readonly receive: TCipherState;
  readonly ctrlSend: TCipherState;
  readonly ctrlReceive: TCipherState;
};

/** `Split()` plus the CTRL key pair (see the module comment). */
const splitKeys = async (
  state: TSymmetricState,
  role: "initiator" | "responder",
): Promise<TTransportKeys> => {
  const [k1, k2] = await hkdf2(state.ck, new Uint8Array());
  const [c1, c2] = await hkdf2(
    state.ck,
    new TextEncoder().encode(CTRL_KEY_INFO),
  );
  const [i2r, r2i, ci2r, cr2i] = await Promise.all([
    aesKey(k1),
    aesKey(k2),
    aesKey(c1),
    aesKey(c2),
  ]);
  return role === "initiator"
    ? {
        send: cipherState(i2r),
        receive: cipherState(r2i),
        ctrlSend: cipherState(ci2r),
        ctrlReceive: cipherState(cr2i),
      }
    : {
        send: cipherState(r2i),
        receive: cipherState(i2r),
        ctrlSend: cipherState(cr2i),
        ctrlReceive: cipherState(ci2r),
      };
};

// ---------------------------------------------------------------------------
// Handshake (IK)
// ---------------------------------------------------------------------------

/** Handshake message transport: one call per whole Noise message. */
type TMessagePipe = {
  readonly send: (message: Uint8Array) => void;
  readonly next: () => Promise<Uint8Array>;
};

type THandshakeResult = TSecureSession & { readonly keys: TTransportKeys };

const prologueOf = (options: TSecureCommonOptions): Uint8Array =>
  options.prologue ?? new TextEncoder().encode(SECURE_DEFAULT_PROLOGUE);

const checkPayloadSize = (payload: Uint8Array): void => {
  if (payload.byteLength > SECURE_MAX_HANDSHAKE_PAYLOAD_BYTES) {
    throw new RangeError("handshake payload exceeds the size cap");
  }
};

const runInitiator = async (
  pipe: TMessagePipe,
  options: TSecureInitiatorOptions,
): Promise<THandshakeResult> => {
  const rs = resolveRemoteStatic(options.remoteStatic);
  const s = options.localStatic ?? (await generateNoiseStaticKey());
  const payload = options.payload ?? new Uint8Array();
  checkPayloadSize(payload);
  const state = await initSymmetric(prologueOf(options), options.psk);
  await mixHash(state, rs);

  // -> e, es, s, ss
  const e = await generateNoiseStaticKey();
  await mixHash(state, e.publicKey);
  if (options.psk !== undefined) await mixKey(state, e.publicKey);
  await mixKey(state, await e.dh(rs));
  const encryptedStatic = await encryptAndHash(state, s.publicKey);
  await mixKey(state, await s.dh(rs));
  const encryptedPayload = await encryptAndHash(state, payload);
  pipe.send(concatBytes(e.publicKey, encryptedStatic, encryptedPayload));

  // <- e, ee, se
  const reply = await pipe.next();
  if (reply.byteLength < NOISE_DH_LEN + NOISE_TAG_LEN) {
    throw new SecureChannelError("malformed", "handshake reply too short");
  }
  const re = reply.slice(0, NOISE_DH_LEN);
  await mixHash(state, re);
  if (options.psk !== undefined) await mixKey(state, re);
  await mixKey(state, await e.dh(re));
  await mixKey(state, await s.dh(re));
  if (options.psk !== undefined) await mixKeyAndHash(state, options.psk);
  const peerPayload = await decryptAndHash(state, reply.subarray(NOISE_DH_LEN));
  return {
    remoteStatic: rs,
    peerPayload,
    handshakeHash: state.h,
    keys: await splitKeys(state, "initiator"),
  };
};

const runResponder = async (
  pipe: TMessagePipe,
  options: TSecureResponderOptions,
): Promise<THandshakeResult> => {
  const s = options.localStatic;
  const state = await initSymmetric(prologueOf(options), options.psk);
  await mixHash(state, s.publicKey);

  // -> e, es, s, ss
  const first = await pipe.next();
  const staticEnd = NOISE_DH_LEN + NOISE_DH_LEN + NOISE_TAG_LEN;
  if (first.byteLength < staticEnd + NOISE_TAG_LEN) {
    throw new SecureChannelError("malformed", "handshake message too short");
  }
  const re = first.slice(0, NOISE_DH_LEN);
  await mixHash(state, re);
  if (options.psk !== undefined) await mixKey(state, re);
  await mixKey(state, await s.dh(re));
  const rs = await decryptAndHash(
    state,
    first.subarray(NOISE_DH_LEN, staticEnd),
  );
  await mixKey(state, await s.dh(rs));
  const peerPayload = await decryptAndHash(state, first.subarray(staticEnd));

  let reply: Uint8Array | null;
  try {
    reply = await options.authorize({ remoteStatic: rs, payload: peerPayload });
  } catch {
    reply = null;
  }
  if (reply === null) {
    throw new SecureChannelError("refused", "initiator refused");
  }
  checkPayloadSize(reply);

  // <- e, ee, se
  const e = await generateNoiseStaticKey();
  await mixHash(state, e.publicKey);
  if (options.psk !== undefined) await mixKey(state, e.publicKey);
  await mixKey(state, await e.dh(re));
  await mixKey(state, await e.dh(rs));
  if (options.psk !== undefined) await mixKeyAndHash(state, options.psk);
  const encryptedPayload = await encryptAndHash(state, reply);
  pipe.send(concatBytes(e.publicKey, encryptedPayload));
  return {
    remoteStatic: rs,
    peerPayload,
    handshakeHash: state.h,
    keys: await splitKeys(state, "responder"),
  };
};

/** Run the handshake under a timeout + abort signal. */
const runHandshake = (
  pipe: TMessagePipe,
  options: TSecureOptions,
  fail: (error: SecureChannelError) => void,
): Promise<THandshakeResult> => {
  const timeoutMs = options.timeoutMs ?? SECURE_HANDSHAKE_TIMEOUT_MS;
  return new Promise<THandshakeResult>((resolve, reject) => {
    let done = false;
    const settle = (
      error: SecureChannelError | null,
      value?: THandshakeResult,
    ): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (error !== null) {
        fail(error);
        reject(error);
        return;
      }
      if (value !== undefined) resolve(value);
    };
    const onAbort = (): void => {
      settle(new SecureChannelError("timeout", "secure handshake aborted"));
    };
    const timer = setTimeout(() => {
      settle(new SecureChannelError("timeout", "secure handshake timed out"));
    }, timeoutMs);
    if (options.signal?.aborted === true) {
      onAbort();
      return;
    }
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const run =
      options.role === "initiator"
        ? runInitiator(pipe, options)
        : runResponder(pipe, options);
    run.then(
      (value) => settle(null, value),
      (error: unknown) =>
        settle(
          error instanceof SecureChannelError
            ? error
            : new SecureChannelError(
                "malformed",
                error instanceof Error ? error.message : "handshake failed",
              ),
        ),
    );
  });
};

/** Inbound message queue that feeds {@link TMessagePipe.next}. */
const createInbox = (): {
  readonly push: (message: Uint8Array) => void;
  readonly fail: (error: SecureChannelError) => void;
  readonly next: () => Promise<Uint8Array>;
  /** Take one queued message without waiting (records behind the handshake). */
  readonly drain: () => Uint8Array | undefined;
  readonly size: () => number;
} => {
  const queued: Uint8Array[] = [];
  let failure: SecureChannelError | null = null;
  let waiter: {
    readonly resolve: (message: Uint8Array) => void;
    readonly reject: (error: SecureChannelError) => void;
  } | null = null;
  return {
    push: (message) => {
      if (waiter !== null) {
        const w = waiter;
        waiter = null;
        w.resolve(message);
        return;
      }
      queued.push(message);
    },
    fail: (error) => {
      if (failure !== null) return;
      failure = error;
      if (waiter !== null) {
        const w = waiter;
        waiter = null;
        w.reject(error);
      }
    },
    next: () => {
      const message = queued.shift();
      if (message !== undefined) return Promise.resolve(message);
      if (failure !== null) return Promise.reject(failure);
      return new Promise<Uint8Array>((resolve, reject) => {
        waiter = { resolve, reject };
      });
    },
    drain: () => queued.shift(),
    size: () => queued.length,
  };
};

// ---------------------------------------------------------------------------
// Carrier 1: message-oriented TDuplex
// ---------------------------------------------------------------------------

/**
 * Run a Noise_IK handshake over `duplex`, then return a {@link TDuplex} that
 * carries plaintext messages end-to-end encrypted. The returned duplex keeps
 * message boundaries; a message larger than one Noise message is split into
 * records and reassembled (up to {@link SECURE_DUPLEX_MAX_MESSAGE_BYTES}).
 *
 * Rejects with {@link SecureChannelError} (and closes `duplex`) when the
 * handshake fails. After it succeeds, an inbound message that fails AEAD
 * closes `duplex` and delivers `null` (peer gone) to the listener.
 *
 * Call it before the peer can send (it subscribes to `duplex.onBytes`).
 */
export const secureDuplex = async (
  duplex: TDuplex,
  options: TSecureOptions & { readonly maxMessageBytes?: number },
): Promise<TSecureDuplex> => {
  const maxMessageBytes =
    options.maxMessageBytes ?? SECURE_DUPLEX_MAX_MESSAGE_BYTES;
  const inbox = createInbox();
  let phase: TSecurePhase = "handshake";
  let listener: ((bytes: Uint8Array | null) => void) | null = null;
  let keys: TTransportKeys | null = null;
  let receiveChain: Promise<void> = Promise.resolve();
  let sendChain: Promise<void> = Promise.resolve();
  let partial: Uint8Array[] = [];
  let partialBytes = 0;

  const pendingMessages: Array<Uint8Array | null> = [];
  const deliver = (bytes: Uint8Array | null): void => {
    if (listener === null) {
      pendingMessages.push(bytes);
      return;
    }
    try {
      listener(bytes);
    } catch {
      // A listener cannot destabilize the carrier.
    }
  };
  const die = (notify: boolean): void => {
    if (phase === "dead") return;
    phase = "dead";
    partial = [];
    duplex.close();
    if (notify) deliver(null);
  };

  const receiveRecord = async (ciphertext: Uint8Array): Promise<void> => {
    if (phase !== "open" || keys === null) return;
    let record: Uint8Array;
    try {
      record = await decryptWithAd(keys.receive, new Uint8Array(), ciphertext);
    } catch {
      die(true);
      return;
    }
    if (phase !== "open") return;
    const flag = record[0];
    if (
      record.byteLength < 1 ||
      (flag !== RECORD_MORE && flag !== RECORD_FINAL)
    ) {
      die(true);
      return;
    }
    const chunk = record.subarray(1);
    partialBytes += chunk.byteLength;
    if (partialBytes > maxMessageBytes) {
      die(true);
      return;
    }
    partial.push(chunk);
    if (flag === RECORD_MORE) return;
    const message = concatBytes(...partial);
    partial = [];
    partialBytes = 0;
    deliver(message);
  };

  duplex.onBytes((bytes) => {
    if (phase === "dead") return;
    if (bytes === null) {
      if (phase === "handshake") {
        inbox.fail(
          new SecureChannelError("closed", "peer closed during handshake"),
        );
        return;
      }
      receiveChain = receiveChain.then(() => {
        if (phase === "dead") return;
        phase = "dead";
        deliver(null);
      });
      return;
    }
    if (phase === "handshake") {
      if (inbox.size() >= SECURE_MAX_EARLY_MESSAGES) {
        inbox.fail(
          new SecureChannelError("malformed", "flooded during handshake"),
        );
        return;
      }
      inbox.push(new Uint8Array(bytes));
      return;
    }
    const copy = new Uint8Array(bytes);
    receiveChain = receiveChain.then(() => receiveRecord(copy));
  });

  const handshake = await runHandshake(
    { send: (message) => duplex.send(message), next: inbox.next },
    options,
    (error) => {
      inbox.fail(error);
      die(false);
    },
  );
  keys = handshake.keys;
  phase = "open";
  // Records that arrived right behind the last handshake message.
  for (;;) {
    const early = inbox.drain();
    if (early === undefined) break;
    receiveChain = receiveChain.then(() => receiveRecord(early));
  }

  const send = (bytes: Uint8Array): void => {
    if (phase !== "open" || keys === null) return;
    const transport = keys;
    const copy = new Uint8Array(bytes);
    sendChain = sendChain.then(async () => {
      let offset = 0;
      do {
        const end = Math.min(offset + DUPLEX_RECORD_PLAINTEXT, copy.byteLength);
        const flag = end < copy.byteLength ? RECORD_MORE : RECORD_FINAL;
        const record = concatBytes(
          new Uint8Array([flag]),
          copy.subarray(offset, end),
        );
        const ciphertext = await encryptWithAd(
          transport.send,
          new Uint8Array(),
          record,
        );
        if (phase !== "open") return;
        duplex.send(ciphertext);
        offset = end;
      } while (offset < copy.byteLength);
    });
  };

  return {
    send,
    bufferedAmount: duplex.bufferedAmount,
    highWaterMark: duplex.highWaterMark,
    onDrain: duplex.onDrain,
    onBytes: (callback) => {
      listener = callback;
      if (pendingMessages.length === 0) return;
      const queued = pendingMessages.splice(0);
      for (const message of queued) deliver(message);
    },
    close: () => {
      die(false);
    },
    remoteStatic: handshake.remoteStatic,
    peerPayload: handshake.peerPayload,
    handshakeHash: handshake.handshakeHash,
  };
};

// ---------------------------------------------------------------------------
// Carrier 2: one mux stream (the agent path over the relay)
// ---------------------------------------------------------------------------

export type TSecureMuxStreamOptions = TSecureOptions & {
  /** RESET code sent when the handshake fails. Defaults to `unauthorized`. */
  readonly handshakeResetCode?: TStreamResetCode;
};

/** Append the Noise spec's 2-byte big-endian length prefix. */
const lengthPrefixed = (message: Uint8Array): Uint8Array => {
  const out = new Uint8Array(LENGTH_PREFIX_BYTES + message.byteLength);
  new DataView(out.buffer).setUint16(0, message.byteLength, false);
  out.set(message, LENGTH_PREFIX_BYTES);
  return out;
};

/** Reassemble length-prefixed records from an arbitrarily chunked byte stream. */
const createRecordReader = (): {
  readonly push: (bytes: Uint8Array) => void;
  readonly next: () => Uint8Array | null;
  readonly buffered: () => number;
} => {
  let buffer: Uint8Array = new Uint8Array();
  return {
    push: (bytes) => {
      buffer =
        buffer.byteLength === 0
          ? new Uint8Array(bytes)
          : concatBytes(buffer, bytes);
    },
    next: () => {
      if (buffer.byteLength < LENGTH_PREFIX_BYTES) return null;
      const length = new DataView(
        buffer.buffer,
        buffer.byteOffset,
        LENGTH_PREFIX_BYTES,
      ).getUint16(0, false);
      const end = LENGTH_PREFIX_BYTES + length;
      if (buffer.byteLength < end) return null;
      const record = buffer.slice(LENGTH_PREFIX_BYTES, end);
      buffer = buffer.slice(end);
      return record;
    },
    buffered: () => buffer.byteLength,
  };
};

const emitAll = <T>(
  handlers: ReadonlySet<T>,
  invoke: (handler: T) => void,
): void => {
  for (const handler of handlers) {
    try {
      invoke(handler);
    } catch {
      // Handlers cannot destabilize the secure carrier.
    }
  }
};

/**
 * Run a Noise_IK handshake over one mux stream's DATA, then return a
 * {@link TMuxStream} whose DATA and CTRL are end-to-end encrypted. Hand the
 * result to the unchanged stream helpers (`acceptAgentStream`,
 * `pumpAgentCommands`, `sendAgentEvent`, …) in place of the raw stream.
 *
 * Call it synchronously from the OPEN handler (serving side) or right after
 * `openStream` (consumer side), before the first `await`: it subscribes to
 * the stream's DATA, and the peer may already be sending.
 *
 * - Handshake failure: RESETs the stream with `handshakeResetCode`
 *   (`unauthorized`) and rejects with {@link SecureChannelError}.
 * - After the handshake, a record or CTRL that fails AEAD (relay tampering,
 *   reordering, replay, truncation at END) RESETs `protocol_error`.
 * - RESET payloads, END and WINDOW stay plaintext; CTRL from the peer that
 *   arrives before the handshake completes is dropped.
 * - Receive credit is returned to the underlying stream only after a record
 *   is decrypted and delivered; `consume` on the wrapper is a no-op.
 */
export const secureMuxStream = async (
  stream: TMuxStream,
  options: TSecureMuxStreamOptions,
): Promise<TSecureMuxStream> => {
  const inbox = createInbox();
  const reader = createRecordReader();
  const dataHandlers = new Set<TMuxEventHandler>();
  const endHandlers = new Set<() => void>();
  const resetHandlers = new Set<TMuxEventHandler>();
  const ctrlHandlers = new Set<TMuxEventHandler>();
  // Plaintext that lands before the caller has registered a handler (the
  // await of secureMuxStream returns, then the peer may already have sent).
  const pendingData: Uint8Array[] = [];
  const pendingCtrl: Uint8Array[] = [];
  let phase: TSecurePhase = "handshake";
  const currentPhase = (): TSecurePhase => phase;
  let keys: TTransportKeys | null = null;
  let receiveChain: Promise<void> = Promise.resolve();
  let ctrlReceiveChain: Promise<void> = Promise.resolve();
  let sendChain: Promise<void> = Promise.resolve();

  const fail = (code: TStreamResetCode, message: string): void => {
    if (phase === "dead") return;
    if (phase === "handshake") {
      inbox.fail(new SecureChannelError("malformed", message));
    }
    phase = "dead";
    // A local reset fires the underlying onReset → our resetHandlers.
    stream.reset(encodeJsonPayload({ code, message }));
  };

  const emitData = (plaintext: Uint8Array): void => {
    if (dataHandlers.size === 0) {
      pendingData.push(plaintext);
      return;
    }
    emitAll(dataHandlers, (handler) => handler(plaintext));
  };
  const emitCtrl = (plaintext: Uint8Array): void => {
    if (ctrlHandlers.size === 0) {
      pendingCtrl.push(plaintext);
      return;
    }
    emitAll(ctrlHandlers, (handler) => handler(plaintext));
  };

  const receiveRecord = async (record: Uint8Array): Promise<void> => {
    if (phase !== "open" || keys === null) return;
    let plaintext: Uint8Array;
    try {
      plaintext = await decryptWithAd(keys.receive, new Uint8Array(), record);
    } catch {
      fail("protocol_error", "secure stream integrity failure");
      return;
    }
    if (phase !== "open") return;
    emitData(plaintext);
    stream.consume(LENGTH_PREFIX_BYTES + record.byteLength);
  };

  const drainRecords = (): void => {
    for (;;) {
      const record = reader.next();
      if (record === null) return;
      if (phase === "handshake") {
        if (inbox.size() >= SECURE_MAX_EARLY_MESSAGES) {
          fail("protocol_error", "flooded during handshake");
          return;
        }
        stream.consume(LENGTH_PREFIX_BYTES + record.byteLength);
        inbox.push(record);
        continue;
      }
      receiveChain = receiveChain.then(() => receiveRecord(record));
    }
  };

  const offData = stream.onData((bytes) => {
    if (phase === "dead") return;
    reader.push(bytes);
    drainRecords();
    // Credit is returned per record once it is delivered.
    return false;
  });
  const offEnd = stream.onEnd(() => {
    if (phase === "handshake") {
      inbox.fail(
        new SecureChannelError("closed", "peer ended during handshake"),
      );
      return;
    }
    receiveChain = receiveChain.then(() => {
      if (phase !== "open") return;
      if (reader.buffered() > 0) {
        fail("protocol_error", "secure stream truncated");
        return;
      }
      emitAll(endHandlers, (handler) => handler());
    });
  });
  const offReset = stream.onReset((payload) => {
    const wasHandshake = phase === "handshake";
    phase = "dead";
    if (wasHandshake) {
      inbox.fail(
        new SecureChannelError("closed", "stream reset during handshake"),
      );
    }
    emitAll(resetHandlers, (handler) => handler(payload));
  });
  const receiveCtrl = (ciphertext: Uint8Array): void => {
    ctrlReceiveChain = ctrlReceiveChain.then(async () => {
      if (phase !== "open" || keys === null) return;
      let plaintext: Uint8Array;
      try {
        plaintext = await decryptWithAd(
          keys.ctrlReceive,
          new Uint8Array(),
          ciphertext,
        );
      } catch {
        fail("protocol_error", "secure stream integrity failure");
        return;
      }
      if (phase !== "open") return;
      emitCtrl(plaintext);
    });
  };
  // The peer finishes its side first and may send CTRL (e.g. `open_ack`)
  // while this side is still processing the last handshake message.
  const earlyCtrl: Uint8Array[] = [];
  const offCtrl = stream.onCtrl((payload) => {
    if (phase === "dead") return;
    const copy = new Uint8Array(payload);
    if (phase === "handshake") {
      if (earlyCtrl.length >= SECURE_MAX_EARLY_CTRL) {
        fail("protocol_error", "too much CTRL before the handshake finished");
        return;
      }
      earlyCtrl.push(copy);
      return;
    }
    receiveCtrl(copy);
  });

  let handshake: THandshakeResult;
  try {
    handshake = await runHandshake(
      {
        send: (message) => {
          void stream.write(lengthPrefixed(message)).catch(() => {});
        },
        next: inbox.next,
      },
      options,
      (error) => {
        inbox.fail(error);
        fail(options.handshakeResetCode ?? "unauthorized", error.message);
      },
    );
  } catch (error) {
    offData();
    offEnd();
    offReset();
    offCtrl();
    throw error;
  }
  // `phase` is mutated by the stream callbacks while the handshake ran.
  if (currentPhase() === "dead") {
    throw new SecureChannelError("closed", "stream reset during handshake");
  }
  keys = handshake.keys;
  phase = "open";
  // Records that arrived right behind the last handshake message.
  for (;;) {
    const early = inbox.drain();
    if (early === undefined) break;
    // Already credited during the handshake phase; decrypt only.
    receiveChain = receiveChain.then(async () => {
      if (phase !== "open" || keys === null) return;
      try {
        const plaintext = await decryptWithAd(
          keys.receive,
          new Uint8Array(),
          early,
        );
        if (phase === "open") emitData(plaintext);
      } catch {
        fail("protocol_error", "secure stream integrity failure");
      }
    });
  }
  for (const ctrl of earlyCtrl.splice(0)) receiveCtrl(ctrl);
  const transport = keys;

  const write = (bytes: Uint8Array): Promise<void> => {
    if (phase !== "open") return Promise.reject(new Error("stream is closed"));
    if (bytes.byteLength === 0) return Promise.resolve();
    const copy = new Uint8Array(bytes);
    // Encrypt in call order and enqueue each record on the mux at once; the
    // returned promise waits for the mux writes (flow-control backpressure)
    // without holding later CTRL behind them.
    const enqueued = sendChain.then(async () => {
      const writes: Promise<void>[] = [];
      for (
        let offset = 0;
        offset < copy.byteLength;
        offset += STREAM_RECORD_PLAINTEXT
      ) {
        const ciphertext = await encryptWithAd(
          transport.send,
          new Uint8Array(),
          copy.subarray(offset, offset + STREAM_RECORD_PLAINTEXT),
        );
        if (phase !== "open") throw new Error("stream is closed");
        writes.push(stream.write(lengthPrefixed(ciphertext)));
      }
      return writes;
    });
    sendChain = enqueued.then(
      () => undefined,
      () => undefined,
    );
    return enqueued.then(async (writes) => {
      await Promise.all(writes);
    });
  };

  return {
    id: stream.id,
    write,
    end: () => {
      sendChain = sendChain.then(() => {
        if (phase === "open") stream.end();
      });
    },
    reset: (payload) => {
      phase = "dead";
      stream.reset(payload);
    },
    sendCtrl: (payload) => {
      if (phase !== "open") return;
      const copy = new Uint8Array(payload);
      sendChain = sendChain.then(async () => {
        const ciphertext = await encryptWithAd(
          transport.ctrlSend,
          new Uint8Array(),
          copy,
        );
        if (phase === "open") stream.sendCtrl(ciphertext);
      });
    },
    consume: () => {},
    onData: (handler) => {
      dataHandlers.add(handler);
      if (pendingData.length > 0) {
        const queued = pendingData.splice(0);
        for (const plaintext of queued) {
          emitAll(dataHandlers, (h) => h(plaintext));
        }
      }
      return () => dataHandlers.delete(handler);
    },
    onEnd: (handler) => {
      endHandlers.add(handler);
      return () => endHandlers.delete(handler);
    },
    onReset: (handler) => {
      resetHandlers.add(handler);
      return () => resetHandlers.delete(handler);
    },
    onCtrl: (handler) => {
      ctrlHandlers.add(handler);
      if (pendingCtrl.length > 0) {
        const queued = pendingCtrl.splice(0);
        for (const plaintext of queued) {
          emitAll(ctrlHandlers, (h) => h(plaintext));
        }
      }
      return () => ctrlHandlers.delete(handler);
    },
    remoteStatic: handshake.remoteStatic,
    peerPayload: handshake.peerPayload,
    handshakeHash: handshake.handshakeHash,
  };
};
