/**
 * The ONE fleet-request consumer, shared by both fleet callers: a peer
 * daemon's walker (`tunnel-client.ts`) and origin's `/v1/*` proxy
 * (`packages/api/lib/origin-tunnel.ts`). Both hand a whole inference request
 * to a device that serves the subscription; the device runs it through the
 * same `serveMuxTunnel` → `handleInference` path and stamps the
 * `x-openllm-tunneled` loop guard because the stream is `consumer:"daemon"`.
 *
 * Transport (RTC vs relay mux, how the channel was opened) stays with the
 * caller; this owns the request mapping and the response shape.
 */
import type {
  TTunnelForwardHeaders,
  TTunnelSurface,
} from "@openllmsh/protocol";
import {
  ALLOWED_TUNNEL_ACCEPT,
  isAllowedTunnelRequestContentType,
} from "@openllmsh/protocol";
import type { TMuxChannel } from "./mux";
import { tunnelStream } from "./streams";

type TAccept = NonNullable<TTunnelForwardHeaders["accept"]>;
const isAccept = (value: string): value is TAccept =>
  (ALLOWED_TUNNEL_ACCEPT as ReadonlyArray<string>).includes(value);

/** Map inbound HTTP headers to the mux's closed forward-header struct. */
export const fleetForwardHeaders = (
  headers: Headers,
): TTunnelForwardHeaders => {
  const accept = headers.get("accept")?.split(",", 1)[0]?.trim();
  const contentType = headers.get("content-type") ?? "";
  const anthropicVersion = headers.get("anthropic-version");
  const anthropicBeta = headers.get("anthropic-beta");
  const userAgent = headers.get("user-agent");
  return {
    ...(isAllowedTunnelRequestContentType(contentType)
      ? { content_type: contentType }
      : {}),
    ...(accept !== undefined && isAccept(accept) ? { accept } : {}),
    ...(anthropicVersion !== null
      ? { anthropic_version: anthropicVersion.slice(0, 32) }
      : {}),
    ...(anthropicBeta !== null ? { anthropic_beta: anthropicBeta } : {}),
    ...(userAgent !== null ? { user_agent: userAgent.slice(0, 512) } : {}),
  };
};

export type TFleetRequest = {
  readonly surface: TTunnelSurface;
  readonly headers: TTunnelForwardHeaders;
  readonly body: Uint8Array;
  readonly signal: AbortSignal;
};

/**
 * Send one fleet request over an open channel. Resolves once the device's
 * response head arrives (body streams thereafter); rejects on any stream
 * failure. The OPEN may already have reached the device when this rejects,
 * so callers must not blindly re-dispatch to a second device.
 */
export const fleetRequest = async (
  channel: TMuxChannel,
  request: TFleetRequest,
): Promise<Response> => {
  const result = await tunnelStream(channel, {
    surface: request.surface,
    headers: request.headers,
    body: request.body,
    signal: request.signal,
    consumer: "daemon",
  });
  return new Response(result.body, {
    status: result.status,
    headers: result.headers,
  });
};
