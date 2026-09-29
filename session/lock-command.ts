import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { TDirLockCodec } from "./dir-lock";
import { acquireDirLockSync } from "./dir-lock";
import { LegacyLockError, lockNonce } from "./dir-lock-control";
import {
  associateLaunchChild,
  handoffLaunchChild,
  runLaunchPublisher,
} from "./dir-lock-launch";
import { writeLockReply as writeResponse } from "./dir-lock-reply";
import { registerVendorGroup } from "./dir-lock-vendor";
import { processIdentityStatus, processStartIdentity } from "./local-runtime";

const helperCodec = (kind: string): TDirLockCodec => ({
  kind,
  ownerFile: "owner.v3",
  readOwner: (): null => null,
  serializeOwner: (): string => {
    throw new Error("the v3 core owns serialization");
  },
});
const envLockMs = (name: string, fallback: number): number => {
  const value = process.env[name];
  const seconds =
    value !== undefined && /^[0-9]+$/.test(value) ? Number(value) : 0;
  return Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 3600
    ? seconds * 1000
    : fallback;
};
export const runInternalLockControl = async (
  args: readonly string[],
): Promise<number> => {
  if (process.platform === "win32") return 74;
  if (args[0] === "vendor-group") {
    if (args.length !== 3 || !/^[1-9][0-9]{0,9}$/.test(args[2] ?? "")) return 2;
    try {
      return registerVendorGroup(args[1] ?? "", Number(args[2]));
    } catch (error) {
      return error instanceof LegacyLockError ? 73 : 74;
    }
  }
  if (args[0] === "launch") {
    if (args.length !== 4) return 2;
    const [, marker, mode, ready] = args;
    if (
      !marker ||
      !ready ||
      !isAbsolute(marker) ||
      !isAbsolute(ready) ||
      (mode !== "mixed" && mode !== "new-only")
    )
      return 2;
    return runLaunchPublisher(marker, mode, ready);
  }
  if (args.length !== 5 && args.length !== 8) return 2;
  const [
    kind,
    path,
    workerPidText,
    request,
    response,
    launchMarker,
    launchNonce,
    maxWaitText,
  ] = args;
  if (
    (kind !== "e" && kind !== "v") ||
    !path ||
    !request ||
    !response ||
    !isAbsolute(path) ||
    !isAbsolute(request) ||
    !isAbsolute(response) ||
    !/^[1-9][0-9]{0,9}$/.test(workerPidText ?? "")
  )
    return 2;
  if (kind === "e" && args.length !== 5) return 2;
  if (
    kind === "v" &&
    (args.length !== 8 ||
      !launchMarker ||
      !isAbsolute(launchMarker) ||
      !/^[0-9a-f]{32}$/.test(launchNonce ?? "") ||
      !/^[1-9][0-9]{0,6}$/.test(maxWaitText ?? ""))
  )
    return 2;
  const maxWaitMs = kind === "v" ? Number(maxWaitText) * 1000 : 30_000;
  if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs > 3_600_000) return 2;
  const workerPid = Number(workerPidText);
  const workerStart = processStartIdentity(workerPid);
  if (workerPid > 2147483647 || typeof workerStart !== "string") return 74;
  // The caller owns the product operation. Keep its identity after helper death.
  const worker = { pid: workerPid, start: workerStart, nonce: lockNonce() };
  const ignoreHup = (): void => {};
  process.on("SIGHUP", ignoreHup);
  let release: (() => void) | null = null;
  try {
    release = acquireDirLockSync(path, helperCodec(kind), {
      waitMs:
        kind === "e" ? envLockMs("OPENLLM_ENV_LOCK_WAIT_SECS", 10_000) : 10_000,
      reclaimMs: 30_000,
      ownerlessMs:
        kind === "e"
          ? envLockMs("OPENLLM_ENV_LOCK_ORPHAN_SECS", 30_000)
          : 30_000,
      pollMs: 25,
      propagatePublishErrors: true,
      worker,
      onStep: (step, _path, owner): void => {
        if (kind !== "v" || !launchMarker || !launchNonce) return;
        if (step === "after-mkdir")
          associateLaunchChild(launchMarker, path, launchNonce, worker);
        if (step === "before-grant") {
          if (!owner)
            throw new Error("vendor owner is unavailable for launch handoff");
          handoffLaunchChild(launchMarker, path, launchNonce, worker, owner);
        }
      },
    });
    if (release === null) {
      writeResponse(response, 74);
      return 74;
    }
    const activeRelease = release;
    writeResponse(response, 0);
    const deadline = performance.now() + maxWaitMs;
    for (
      let attempt = 0;
      attempt < Math.ceil(maxWaitMs / 50) && performance.now() < deadline;
      attempt++
    ) {
      try {
        const stat = lstatSync(request);
        if (
          !stat.isFile() ||
          stat.isSymbolicLink() ||
          stat.uid !== process.getuid?.() ||
          stat.size > 32
        )
          return 74;
        const action = readFileSync(request, "utf8");
        if (kind === "v" && action === "preserve\n") return 74;
        if (action !== "release\n") return 2;
        activeRelease();
        release = null;
        return 0;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      if (processIdentityStatus(worker.pid, worker.start) === "dead") {
        // A vendor worker can leave its detached process group alive. Its
        // death alone cannot release the vendor claim.
        if (kind === "v") return 74;
        activeRelease();
        release = null;
        return 74;
      }
      await Bun.sleep(Math.min(50, Math.max(0, deadline - performance.now())));
    }
    // Keep the worker association. A timeout does not prove product completion.
    return 74;
  } catch (error) {
    const code = error instanceof LegacyLockError ? 73 : 74;
    try {
      writeResponse(response, code);
    } catch {
      /* Preserve the first response. */
    }
    process.stderr.write(
      `${error instanceof Error ? error.message : "lock helper failed"}\n`,
    );
    return code;
  } finally {
    process.off("SIGHUP", ignoreHup);
  }
};
