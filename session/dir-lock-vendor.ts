import { isAbsolute } from "node:path";
import {
  checkedNames,
  childDirectory,
  childExists,
  closeLockControl,
  LockUnknownError,
  lockGeneration,
  openLockControl,
  readRecord,
  withLockGate,
} from "./dir-lock-control";
import {
  decodeDirLockActor,
  encodeDirLockActor,
  formatDirLockTransactionName,
  parseDirLockOwnerRecord,
} from "./dir-lock-format";
import type { TDirectoryHandle } from "./dir-lock-fs";
import {
  close,
  currentProcessGroup,
  mkdirChild,
  removeEmptyChild,
} from "./dir-lock-fs";
import { inspectLegacyHold } from "./dir-lock-legacy";
import { processBootIdentity, processIdentityStatus } from "./local-runtime";

const parseGroup = (
  name: string,
): { readonly pid: number; readonly boot: string | undefined } | null => {
  const match =
    /^group\.v3\.([1-9][0-9]{0,9})(?:\.([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}))?$/.exec(
      name,
    );
  const pid = Number(match?.[1]);
  return match && pid > 1 && pid <= 2147483647 ? { pid, boot: match[2] } : null;
};
const groupEnded = (pid: number): boolean => {
  try {
    process.kill(-pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
};

// The worker cannot start a pipeline until its group is registered.
export const removeEndedVendorGroups = (
  transaction: TDirectoryHandle,
  inspectOnly = false,
  ownerStart?: string,
): boolean => {
  if (!childExists(transaction, "groups.v3")) return false;
  const groups = childDirectory(transaction, "groups.v3");
  try {
    const entries = checkedNames(groups, 1);
    const currentBoot = processBootIdentity();
    const claimBoot = /^boot:([0-9a-f-]{36}):[0-9]+$/.exec(
      ownerStart ?? "",
    )?.[1];
    for (const entry of entries) {
      const group = parseGroup(entry);
      if (group === null) return false;
      const recordedBoot = group.boot ?? claimBoot;
      const previousBoot =
        recordedBoot !== undefined &&
        currentBoot !== undefined &&
        recordedBoot !== currentBoot;
      if (!previousBoot && !groupEnded(group.pid)) return false;
      const record = childDirectory(groups, entry);
      try {
        checkedNames(record, 0);
      } finally {
        close(record);
      }
    }
    if (inspectOnly) return true;
    for (const entry of entries) removeEmptyChild(groups, entry);
  } finally {
    close(groups);
  }
  removeEmptyChild(transaction, "groups.v3");
  return true;
};

export const registerVendorGroup = (
  path: string,
  workerPid: number,
): number => {
  if (
    process.platform === "win32" ||
    !isAbsolute(path) ||
    !Number.isSafeInteger(workerPid) ||
    workerPid <= 0 ||
    workerPid > 2147483647
  )
    return 2;
  const boot = processBootIdentity();
  if (boot === undefined) return 74;
  const name = `group.v3.${currentProcessGroup()}.${boot}`;
  const ctx = openLockControl(path, "v");
  try {
    return (
      withLockGate(ctx, (): number => {
        inspectLegacyHold(ctx);
        const dir = childDirectory(ctx.parent, ctx.base);
        try {
          const owner = parseDirLockOwnerRecord(
            readRecord(dir, "owner.v3", 1024),
          );
          if (!owner || owner.kind !== "v") return 74;
          const token = encodeDirLockActor(owner);
          if (
            childExists(ctx.control, `c.v3.v.${token}`) ||
            childExists(ctx.control, `x.v3.v.${token}`)
          )
            return 74;
          const transaction = childDirectory(
            ctx.control,
            formatDirLockTransactionName({
              kind: "v",
              operation: "p",
              actor: owner,
              generation: lockGeneration(dir),
            }),
          );
          try {
            const workers = checkedNames(transaction, 4).filter((entry) =>
              entry.startsWith("worker.v3."),
            );
            if (workers.length !== 1) return 74;
            const worker = decodeDirLockActor(workers[0]?.slice(10) ?? "");
            if (
              !worker ||
              worker.pid !== workerPid ||
              processIdentityStatus(worker.pid, worker.start) !== "alive"
            )
              return 74;
            const groups = childDirectory(transaction, "groups.v3");
            try {
              if (checkedNames(groups, 1).length !== 0) return 74;
              mkdirChild(groups, name);
            } finally {
              close(groups);
            }
            return 0;
          } finally {
            close(transaction);
          }
        } finally {
          close(dir);
        }
      }) ?? 74
    );
  } catch (error) {
    if (error instanceof LockUnknownError) return 74;
    throw error;
  } finally {
    closeLockControl(ctx);
  }
};
