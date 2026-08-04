# `packages/tunnel` Architecture

> `@openllmsh/tunnel` is the P1 sans-I/O binary mux used between a consumer,
> the blind relay, and a serving daemon. It depends directly only on
> `@openllmsh/protocol` (which owns the Effect Schema contract): no DOM,
> WebSocket implementation, Bun, timers, crypto transport, database, proxy
> pipeline, or framework.

| Layer | Responsibility | Must not know |
| --- | --- | --- |
| `codec.ts` | Frozen binary frame layout and bounded JSON/window helpers | Stream semantics or payload schemas |
| `channel-envelope.ts` | 16-byte channel-UUID wrapper around a WHOLE relay-WS message (`mux2`), so one relay socket multiplexes several channels | Mux stream/flow semantics or payload schemas |
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

The relay authorizes a channel at setup, then routes binary messages by the
nine-byte frame inspection only (never `mux.ts`, JSON, stream kinds, or flow
control). Application payloads and stream state stay endpoint-private.

Routing keys on socket identity for a legacy (`mux1`) channel — the ONE channel
that socket holds. `mux2` peers instead prepend the **channel-id envelope**
(`channel-envelope.ts`) to every binary message, so a socket can hold several
channels at once; the relay demuxes by the tag (verifying the sender actually
owns that channel — the tag is never trusted alone) and re-frames per receiver:
it strips the envelope for a `mux1` peer and adds it for a `mux2` peer, so a
`mux2` serving daemon never needs to learn a browser/fleet consumer's caps.
The frozen mux codec is UNTOUCHED — the envelope wraps whole WebSocket messages,
not mux frames. RTC data channels are never enveloped (no relay hop — the data
channel itself is the channel).

## Landed vs future modules

**Landed on this branch (beyond the frozen mux core):**

- `device-grant.ts` — seed-gated device-access grant wire format (signed by the
  browser vault; verified by the daemon). Capability negotiation uses
  `seedgate1` from `@openllmsh/protocol`.
- `rtc-auth.ts` / `rtc-duplex.ts` — WebRTC fingerprint-bound offer/answer shapes
  and a thin data-channel duplex. Hosts own signaling and crypto: the browser
  and consuming fleet daemon are offerers, while the serving daemon's `rtc-host`
  is the answerer. This is the one direct-path stack for browser↔daemon and
  daemon↔daemon traffic; relay binary mux is the fallback rung when RTC is
  unavailable (consumers do not use a JSON splice — see
  `@packages/daemon-relay/ARCHITECTURE.md`).

**Still future (not present in this package):**

- `secure.ts` — Noise_IK duplex wrapper (P2). Noise wraps complete mux frames as
  plaintext messages, so it needs **no reserved mux-header fields**; the frozen
  nine-byte layout remains unchanged.
- `paths.ts` — multi-path resolver (loopback → LAN → relay) for later direct-path
  work (P3).
