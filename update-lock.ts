/** Cross-process lock for the CLI binary swap region. */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  acquireDirLock,
  moveDirNoReplace,
  sweepDirLockResidue,
  type TDirLockCodec,
  type TDirLockOptions,
  type TDirLockOwner,
  type TDirLockRelease,
  tryAcquireDirLock,
} from "./session/dir-lock";
import { v3DirLockCodec } from "./session/dir-lock-v3";
import type { TProcessStartIdentityReader } from "./session/local-runtime";
import {
  legacyProcessStartIdentity,
  processStartIdentity,
} from "./session/local-runtime";

export const updateLockDirFor = (destPath: string): string =>
  `${destPath}.update.lock`;
export const UPDATE_LOCK_WAIT_MS = 30_000;
export const UPDATE_LOCK_RECLAIM_MS = 10 * 60_000;

export type TUpdateLockOptions = {
  readonly waitMs?: number;
  readonly reclaimMs?: number;
  readonly now?: () => number;
  readonly elapsedNow?: () => number;
  readonly wallNow?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly pidAlive?: (pid: number) => boolean;
  readonly startIdentity?: TProcessStartIdentityReader;
  readonly legacyStartIdentity?: TProcessStartIdentityReader;
};
export type TUpdateLockRelease = TDirLockRelease;

const UPDATE_KIND = "openllm-update-lock/v1";
const ownerFromJson = (value: string): TDirLockOwner | null => {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed !== "object" || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    if (
      record.kind !== UPDATE_KIND ||
      typeof record.pid !== "number" ||
      !Number.isSafeInteger(record.pid) ||
      record.pid <= 0 ||
      typeof record.start !== "string" ||
      typeof record.nonce !== "string" ||
      record.nonce.length === 0
    )
      return null;
    return {
      kind: UPDATE_KIND,
      pid: record.pid,
      start: record.start,
      nonce: record.nonce,
    };
  } catch {
    return null;
  }
};

const updateCodec: TDirLockCodec =
  process.platform !== "win32"
    ? v3DirLockCodec("u")
    : {
        kind: UPDATE_KIND,
        ownerFile: "owner.json",
        readOwner: (dir: string): TDirLockOwner | null => {
          try {
            const published = ownerFromJson(
              readFileSync(join(dir, "owner.json"), "utf8"),
            );
            if (published !== null) return published;
          } catch {
            // A publish may have stopped after the temp write.
          }
          try {
            const temps = readdirSync(dir)
              .filter(
                (name) =>
                  name.startsWith("owner.json.") && name.endsWith(".tmp"),
              )
              .map((name) =>
                ownerFromJson(readFileSync(join(dir, name), "utf8")),
              )
              .filter((owner): owner is TDirLockOwner => owner !== null);
            return temps.length === 1 ? (temps[0] ?? null) : null;
          } catch {
            return null;
          }
        },
        serializeOwner: (owner: TDirLockOwner): string => JSON.stringify(owner),
      };

let stealGapHook: ((lockDir: string) => void) | null = null;
let restoreGapHook: ((from: string, to: string) => void) | null = null;
export const setUpdateLockStealGapHookForTests = (
  hook: ((lockDir: string) => void) | null,
): void => {
  stealGapHook = hook;
};
export const setUpdateLockMoveBackGapHookForTests = (
  hook: ((from: string, to: string) => void) | null,
): void => {
  restoreGapHook = hook;
};

const options = (value: TUpdateLockOptions = {}): TDirLockOptions => {
  const identity = value.startIdentity ?? processStartIdentity;
  return {
    waitMs: value.waitMs ?? UPDATE_LOCK_WAIT_MS,
    reclaimMs: value.reclaimMs ?? UPDATE_LOCK_RECLAIM_MS,
    pollMs: 250,
    propagatePublishErrors: true,
    now: value.now,
    elapsedNow: value.elapsedNow,
    wallNow: value.wallNow,
    sleep: value.sleep,
    pidAlive: value.pidAlive,
    startIdentity: identity,
    legacyStartIdentity:
      value.legacyStartIdentity ?? legacyProcessStartIdentity,
    ownerStartIdentity: processStartIdentity,
    onRestore: (from, to): void => restoreGapHook?.(from, to),
    onStep: (step, path): void => {
      if (step === "after-steal-marker" || step === "after-steal-rename")
        stealGapHook?.(path.replace(/\.steal-[0-9]+-[0-9a-f]+$/, ""));
    },
  };
};

export const tryAcquireUpdateLock = (
  lockDir: string,
  opts?: {
    readonly startIdentity?: TProcessStartIdentityReader;
    readonly legacyStartIdentity?: TProcessStartIdentityReader;
  },
): TUpdateLockRelease | null =>
  tryAcquireDirLock(
    lockDir,
    updateCodec,
    options({
      startIdentity: opts?.startIdentity,
      legacyStartIdentity: opts?.legacyStartIdentity,
    }),
  );

export const acquireUpdateLock = async (
  lockDir: string,
  opts: TUpdateLockOptions = {},
): Promise<TUpdateLockRelease | null> =>
  acquireDirLock(lockDir, updateCodec, options(opts));

export const withUpdateLock = async <T>(
  lockDir: string,
  opts: TUpdateLockOptions,
  work: () => Promise<T>,
): Promise<T | null> => {
  const release = await acquireUpdateLock(lockDir, opts);
  if (release === null) return null;
  try {
    return await work();
  } finally {
    release();
  }
};

export const sweepUpdateLockResidueForTests = (lockDir: string): void =>
  sweepDirLockResidue(lockDir, updateCodec, options({ waitMs: 0 }));

export const moveUpdateLockNoReplaceForTests = (
  from: string,
  to: string,
): boolean => moveDirNoReplace(from, to, updateCodec);
