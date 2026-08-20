<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./assets/openllm-light.svg">
    <img alt="OpenLLM" src="./assets/openllm.svg" width="300">
  </picture>
</p>

<p align="center"><b>tunnel</b> — the sans-I/O binary mux behind OpenLLM.</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: BUSL-1.1" src="https://img.shields.io/badge/license-BUSL--1.1-blue.svg"></a>
  <img alt="source-available" src="https://img.shields.io/badge/source-available-informational.svg">
</p>

---

The frozen binary mux used between a consumer, the blind relay, and a
serving daemon — frame codec, per-stream flow control, tunnel stream
helpers, device-grant wire, and RTC auth/duplex. No DOM, no WebSocket
implementation, no timers, no crypto transport:

- nine-byte big-endian frame header (`type | stream_id | length`)
- channel-id envelope so one relay socket multiplexes several channels
- per-stream credits, lifecycle, parity, backpressure
- device-grant encode/decode and RTC fingerprint-binding shapes

Depends only on [`@openllmsh/protocol`](https://github.com/openllmsh/protocol).

## Install

```sh
bun install github:openllmsh/tunnel # latest
```

## License

**Source-available** under the [Business Source License 1.1](./LICENSE)
(© OpenLLM, INC) — use it freely except to run a competing hosted service;
converts to MIT on the Change Date. This is not OSI open-source.

---

> **Read-only mirror.** Regenerated from the OpenLLM monorepo each release.
> PRs welcome — ingested upstream with your authorship preserved. BUSL
> contributions require the CLA (the bot will prompt you).
