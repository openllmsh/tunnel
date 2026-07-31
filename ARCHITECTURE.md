# `packages/tunnel` Architecture

> `@openllmsh/tunnel` is the P1 sans-I/O binary mux used between a consumer,
> the blind relay, and a serving daemon. It depends directly only on
> `@openllmsh/protocol` (which owns the Effect Schema contract): no DOM,
> WebSocket implementation, Bun, timers, crypto transport, database, proxy
> pipeline, or framework.

| Layer | Responsibility | Must not know |
| --- | --- | --- |
| `codec.ts` | Frozen binary frame layout and bounded JSON/window helpers | Stream semantics or payload schemas |
| `mux.ts` | Per-stream credits, lifecycle, parity, backpressure; optional sender-side `maxPayloadBytes` for SCTP-sized transports | Tunnel payload shape or host I/O |
| `streams.ts` | OPEN/CTRL/RESET helpers and fetch-shaped tunnel stream APIs (`tunnelStream` / `serveStream`) | Relay routing and WebSocket mechanics |
| `device-grant.ts` | Canonical device-grant envelope encode/decode + message bytes (no crypto) | Vault DEK, node:crypto, host I/O |
| `rtc-duplex.ts` | ~20-line `TDuplex` over `RTCDataChannel` (DOM or werift) | Mux / payload schemas / auth |
| `rtc-auth.ts` | Pure fingerprint-binding shapes + SDP helpers; hosts supply seal/open | Crypto implementations, signaling |

## Wire contract

Every WebSocket binary **message is exactly one mux frame**. The frozen header
is nine bytes, big-endian: `type(u8) | stream_id(u32) | length(u32)`, followed
by exactly `length` payload bytes. The relay validates only this header and
forwards the original bytes; there is no byte-stream reassembly.

OPEN, CTRL, and RESET use UTF-8 JSON in P1. DATA is opaque bytes. END has an
empty payload. WINDOW is exactly one u32 big-endian delta. Numeric constants
have one home in `codec.ts`:

- maximum payload and initial per-stream credit: 256 KiB;
- receiver replenishment threshold: 128 KiB;
- stream zero is channel CTRL; odd ids are consumer initiated and even ids are
  daemon initiated.

## Relay blindness

The relay authorizes one channel at setup, then routes binary messages by socket
identity plus the nine-byte frame inspection only. It does not import `mux.ts`,
decode JSON, learn stream kinds, or apply flow control. This is an invariant:
application payloads and stream state stay endpoint-private.

## Landed vs future modules

**Landed on this branch (beyond the frozen mux core):**

- `device-grant.ts` — seed-gated device-access grant wire format (signed by the
  browser vault; verified by the daemon). Capability negotiation uses
  `seedgate1` from `@openllmsh/protocol`.
- `rtc-auth.ts` / `rtc-duplex.ts` — WebRTC fingerprint-bound offer/answer shapes
  and a thin data-channel duplex. Hosts own signaling and crypto: the browser
  and consuming fleet daemon are offerers, while the serving daemon's `rtc-host`
  is the answerer. This is the one direct-path stack for browser↔daemon and
  daemon↔daemon traffic; relay binary mux and JSON splice remain the fallback
  ladder.

**Still future (not present in this package):**

- `secure.ts` — Noise_IK duplex wrapper (P2). Noise wraps complete mux frames as
  plaintext messages, so it needs **no reserved mux-header fields**; the frozen
  nine-byte layout remains unchanged.
- `paths.ts` — multi-path resolver (loopback → LAN → relay) for later direct-path
  work (P3).
