/**
 * P1 binary tunnel mux + RTC transport helpers.
 * `secure.ts` (Noise_IK duplex wrapper), `grant.ts`, and `paths.ts` remain
 * reserved P2/P3 slots and intentionally do not exist yet. RTC rides the
 * existing mux via {@link rtcDuplex}; fingerprint binding is pure helpers in
 * `rtc-auth.ts` (hosts supply seal/open).
 */
export * from "./codec";
export * from "./mux";
export * from "./rtc-auth";
export * from "./rtc-duplex";
export * from "./streams";
