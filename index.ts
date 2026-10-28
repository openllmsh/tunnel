/**
 * P1 binary tunnel mux + RTC transport helpers, plus the P2 Noise_IK
 * carriers in `secure.ts` (E2E for agent streams on the relay mux).
 * `grant.ts` and `paths.ts` remain reserved P3 slots and intentionally do
 * not exist yet. RTC rides the
 * existing mux via {@link rtcDuplex}; fingerprint binding is pure helpers in
 * `rtc-auth.ts` (hosts supply seal/open).
 */
export * from "./channel-envelope";
export * from "./codec";
export * from "./device-anchor";
export * from "./device-control";
export * from "./device-grant";
export * from "./mux";
export * from "./peer-link";
export * from "./rtc-auth";
export * from "./rtc-duplex";
export * from "./secure";
export * from "./stream-reset-error";
export * from "./streams";
export * from "./team-grant";
export * from "./wire-bytes";
