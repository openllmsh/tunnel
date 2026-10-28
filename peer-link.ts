import type { TMuxChannel } from "./mux";

/** Shared timeout and retention policy for RTC→relay-mux peer links. */
export const PEER_LINK_DEFAULTS = {
  muxAckSameUserMs: 5_000,
  muxAckCrossUserMs: 3_000,
  rtcSignalingMs: 10_000,
  rtcIceMs: 20_000,
  idleTtlMs: 90_000,
  failureTtlMs: 60_000,
} as const;

export type TPeerLinkPath = "rtc" | "mux";
export type TPeerLinkRtcMode = "use-if-open+warm" | "probe";
export type TPeerLinkFailureReason =
  | "aborted"
  | "not_capable"
  | "overloaded"
  | "tunnel_busy"
  | "transport"
  | "unknown";

export type TPeerLinkEvent = {
  readonly type: "selected" | "failed" | "fallback" | "released";
  readonly path: TPeerLinkPath;
  readonly reason?: TPeerLinkFailureReason;
  readonly reused: boolean;
  readonly openMs?: number;
};

export type TPeerLinkDialer = {
  /** A live channel can be selected without spending the open budget. */
  readonly open: () => TMuxChannel | null;
  /** Begins a best-effort warm-up; it must not reject the caller's request. */
  readonly warm?: () => void;
  /** Dials (or joins) a channel. `null` means this rung is unavailable. */
  readonly dial: (timeoutMs: number) => Promise<TMuxChannel | null>;
  /** Host teardown hook for a channel that failed before dispatch. */
  readonly drop?: (channel: TMuxChannel) => void;
};

export type TPeerLinkPolicy = {
  readonly rtcMode?: TPeerLinkRtcMode;
  /** The total time a `probe` call may spend across its rungs. */
  readonly openBudgetMs?: number;
  readonly rtcProbeMs?: number;
  readonly idleTtlMs?: number;
  readonly classifyFailure?: (error: unknown) => TPeerLinkFailureReason;
  /** False means a failed attempt may already have dispatched work. */
  readonly retrySafe?: (error: unknown) => boolean;
  readonly now?: () => number;
};

export type TPeerLinkOptions = {
  /** Stable peer identity; scopes the shared failure cache. */
  readonly target: string;
  readonly rtc?: TPeerLinkDialer;
  readonly mux: TPeerLinkDialer;
  readonly policy?: TPeerLinkPolicy;
  readonly onEvent?: (event: TPeerLinkEvent) => void;
};

export type TPeerLinkChannel = {
  readonly channel: TMuxChannel;
  readonly path: TPeerLinkPath;
  readonly reused: boolean;
  /** Starts idle retention after the caller's last stream finishes. */
  readonly release: () => void;
};

const failureTtlMs = (reason: TPeerLinkFailureReason): number => {
  switch (reason) {
    case "aborted":
      return 0;
    case "overloaded":
    case "tunnel_busy":
      return 2_000;
    case "not_capable":
      return 5_000;
    default:
      return PEER_LINK_DEFAULTS.failureTtlMs;
  }
};

const failureCache = new Map<string, number>();

const cacheKeyOf = (target: string, path: TPeerLinkPath): string =>
  `${target}\u0000${path}`;

/** Shared negative-cache operations for host dialers outside a ladder instance. */
export const peerLinkFailureCache = {
  clear(target?: string): void {
    if (target === undefined) {
      failureCache.clear();
      return;
    }
    for (const key of failureCache.keys()) {
      if (key.startsWith(`${target}\u0000`)) failureCache.delete(key);
    }
  },
  has(target: string, path: TPeerLinkPath, now = Date.now()): boolean {
    const key = cacheKeyOf(target, path);
    const until = failureCache.get(key);
    if (until === undefined) return false;
    if (until > now) return true;
    failureCache.delete(key);
    return false;
  },
  set(
    target: string,
    path: TPeerLinkPath,
    reason: TPeerLinkFailureReason,
    now = Date.now(),
  ): void {
    const ttl = failureTtlMs(reason);
    if (ttl > 0) failureCache.set(cacheKeyOf(target, path), now + ttl);
  },
};

const defaultReasonOf = (error: unknown): TPeerLinkFailureReason => {
  if (error instanceof DOMException && error.name === "AbortError") {
    return "aborted";
  }
  if (!(error instanceof Error)) return "unknown";
  if (error.message.includes("not_capable")) return "not_capable";
  if (error.message.includes("overloaded")) return "overloaded";
  if (error.message.includes("tunnel_busy")) return "tunnel_busy";
  return "transport";
};

/**
 * Sans-I/O RTC-first channel ladder. Hosts provide their RTC and relay mechanics;
 * this module owns selection, bounded probing, negative caching and idle release.
 */
export const createPeerLink = (options: TPeerLinkOptions) => {
  const now = options.policy?.now ?? Date.now;
  const rtcMode = options.policy?.rtcMode ?? "use-if-open+warm";
  const openBudgetMs =
    options.policy?.openBudgetMs ?? PEER_LINK_DEFAULTS.muxAckSameUserMs;
  const rtcProbeMs =
    options.policy?.rtcProbeMs ?? Math.min(2_000, openBudgetMs);
  const idleTtlMs = options.policy?.idleTtlMs ?? PEER_LINK_DEFAULTS.idleTtlMs;
  const classify = options.policy?.classifyFailure ?? defaultReasonOf;
  const retrySafe = options.policy?.retrySafe ?? (() => true);
  const idleTimers = new Map<TMuxChannel, ReturnType<typeof setTimeout>>();

  const emit = (event: TPeerLinkEvent): void => options.onEvent?.(event);
  const cached = (path: TPeerLinkPath): boolean =>
    peerLinkFailureCache.has(options.target, path, now());
  const cache = (path: TPeerLinkPath, error: unknown): void => {
    const reason = classify(error);
    peerLinkFailureCache.set(options.target, path, reason, now());
    emit({ type: "failed", path, reason, reused: false });
  };
  const release = (
    path: TPeerLinkPath,
    dialer: TPeerLinkDialer,
    channel: TMuxChannel,
  ): void => {
    const prior = idleTimers.get(channel);
    if (prior !== undefined) clearTimeout(prior);
    idleTimers.set(
      channel,
      setTimeout(() => {
        idleTimers.delete(channel);
        if (channel.openStreamCount() === 0) dialer.drop?.(channel);
      }, idleTtlMs),
    );
    emit({ type: "released", path, reused: true });
  };
  const resultOf = (
    path: TPeerLinkPath,
    dialer: TPeerLinkDialer,
    channel: TMuxChannel,
    reused: boolean,
    openedAt: number,
  ): TPeerLinkChannel => {
    const prior = idleTimers.get(channel);
    if (prior !== undefined) {
      clearTimeout(prior);
      idleTimers.delete(channel);
    }
    emit({ type: "selected", path, reused, openMs: now() - openedAt });
    return {
      channel,
      path,
      reused,
      release: () => release(path, dialer, channel),
    };
  };

  const channel = async (): Promise<TPeerLinkChannel | null> => {
    const startedAt = now();
    const rtc = options.rtc;
    if (rtc !== undefined && !cached("rtc")) {
      const open = rtc.open();
      if (open !== null) return resultOf("rtc", rtc, open, true, startedAt);
      rtc.warm?.();
      if (rtcMode === "probe") {
        try {
          const probe = await rtc.dial(Math.min(rtcProbeMs, openBudgetMs));
          if (probe !== null)
            return resultOf("rtc", rtc, probe, false, startedAt);
        } catch (error) {
          cache("rtc", error);
          emit({
            type: "fallback",
            path: "rtc",
            reason: classify(error),
            reused: false,
          });
        }
      }
    }
    if (cached("mux")) return null;
    const remaining = Math.max(0, openBudgetMs - (now() - startedAt));
    if (remaining === 0) return null;
    try {
      const mux = await options.mux.dial(remaining);
      if (mux === null) return null;
      return resultOf(
        "mux",
        options.mux,
        mux,
        options.mux.open() === mux,
        startedAt,
      );
    } catch (error) {
      cache("mux", error);
      return null;
    }
  };

  const attempt = async <T>(
    fn: (resolved: TPeerLinkChannel) => Promise<T>,
  ): Promise<T> => {
    const resolved = await channel();
    if (resolved === null) throw new Error("peer link unavailable");
    try {
      return await fn(resolved);
    } catch (error) {
      if (!retrySafe(error)) throw error;
      cache(resolved.path, error);
      resolved.release();
      if (resolved.path !== "rtc") throw error;
      emit({
        type: "fallback",
        path: "rtc",
        reason: classify(error),
        reused: resolved.reused,
      });
      const mux = await channel();
      if (mux === null || mux.path !== "mux") throw error;
      return fn(mux);
    }
  };

  return {
    channel,
    attempt,
    clearFailures: (): void => peerLinkFailureCache.clear(options.target),
  };
};

export const peerLinkFailureTtl = failureTtlMs;
