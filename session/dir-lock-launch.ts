import { fsyncSync, writeFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { TDirLockOwner } from "./dir-lock";
import type { TLockControl } from "./dir-lock-control";
import {
  checkedNames,
  childDirectory,
  childExists,
  closeLockControl,
  errorCode,
  LegacyLockError,
  LockUnknownError,
  lockGeneration,
  lockNonce,
  openLockControl,
  readRecord,
  withLockGate,
  writeRecord,
} from "./dir-lock-control";
import type { TDirLockActor, TDirLockClaim } from "./dir-lock-format";
import {
  decodeDirLockActor,
  encodeDirLockActor,
  formatDirLockTransactionName,
  parseDirLockOwnerRecord,
  parseDirLockPlan,
  parseDirLockTransactionName,
  serializeDirLockOwnerRecord,
  serializeDirLockPlan,
} from "./dir-lock-format";
import type { TDirectoryHandle } from "./dir-lock-fs";
import {
  close,
  linkChild,
  mkdirChild,
  openChild,
  openDirectory,
  posixOpenFlags,
  removeEmptyChild,
  statDescriptor,
  unlinkChild,
} from "./dir-lock-fs";
import { inspectLegacyHold } from "./dir-lock-legacy";
import { writeLockReply } from "./dir-lock-reply";
import { processIdentityStatus, processStartIdentity } from "./local-runtime";

export type TLaunchMode = "mixed" | "new-only";
export const INCOMPLETE_LAUNCH_MESSAGE =
  "launch handoff is incomplete; stop all older installers and their workers, then rerun this installer with `--lock-participants=new-only` to recover the new launch marker";
const READY_WAIT_MS = 30_000;
const MAX_CONTROL = 512;
const pause = (ms: number): Promise<void> => Bun.sleep(ms);

type TLaunchEvidence = {
  readonly transactionName: string;
  readonly transaction: TDirectoryHandle;
  readonly claim: TDirLockClaim;
  readonly tempName: string;
  readonly publicBytes: Buffer | null;
  readonly tempBytes: Buffer | null;
  readonly publicGeneration: string | null;
  readonly tempGeneration: string | null;
  readonly names: readonly string[];
};

function fileGeneration(dir: TDirectoryHandle, name: string): string | null {
  try {
    const file = openChild(dir, name, posixOpenFlags().O_RDONLY);
    try {
      const stat = statDescriptor(file.fd);
      if (!stat.isFile())
        throw new LockUnknownError("launch marker has an unsafe type");
      return `${stat.dev.toString(16).padStart(16, "0")}.${stat.ino.toString(16).padStart(16, "0")}`;
    } finally {
      close(file);
    }
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
}

function fileBytes(dir: TDirectoryHandle, name: string): Buffer | null {
  try {
    return readRecord(dir, name, 1024);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
}

function transactionFor(
  ctx: TLockControl,
  nonce: string,
): TLaunchEvidence | null {
  const names = checkedNames(ctx.control, MAX_CONTROL);
  const transactions = names
    .map(parseDirLockTransactionName)
    .filter(
      (entry) =>
        entry?.kind === "a" &&
        entry.operation === "p" &&
        entry.actor.nonce === nonce,
    );
  if (transactions.length !== 1) return null;
  const descriptor = transactions[0];
  if (!descriptor) return null;
  const transactionName = formatDirLockTransactionName(descriptor);
  const transaction = childDirectory(ctx.control, transactionName);
  try {
    const plan = parseDirLockPlan(
      readRecord(transaction, "plan.v3.json", 8192),
    );
    if (
      !plan ||
      plan.operation !== "p" ||
      plan.basis !== "absent" ||
      plan.target !== ctx.base ||
      plan.generation !== lockGeneration(ctx.parent) ||
      descriptor.generation !== plan.generation
    )
      throw new LockUnknownError("launch transaction association failed");
    const claim: TDirLockClaim = { kind: "a", ...descriptor.actor };
    const tempName = `${ctx.base}.${claim.nonce}.tmp`;
    const publicBytes = fileBytes(ctx.parent, ctx.base);
    const tempBytes = fileBytes(ctx.parent, tempName);
    const publicGeneration = fileGeneration(ctx.parent, ctx.base);
    const tempGeneration = fileGeneration(ctx.parent, tempName);
    return {
      transactionName,
      transaction,
      claim,
      tempName,
      publicBytes,
      tempBytes,
      publicGeneration,
      tempGeneration,
      names: checkedNames(transaction, 8),
    };
  } catch (error) {
    close(transaction);
    throw error;
  }
}

function validatePublication(
  ctx: TLockControl,
  evidence: TLaunchEvidence,
  allowMissingTemp = false,
  allowUnrecordedLink = false,
): void {
  const { publicBytes, tempBytes, publicGeneration, tempGeneration, claim } =
    evidence;
  if (
    !publicBytes ||
    !publicGeneration ||
    (tempBytes === null || tempGeneration === null
      ? !allowMissingTemp || tempBytes !== null || tempGeneration !== null
      : publicGeneration !== tempGeneration || !publicBytes.equals(tempBytes))
  )
    throw new LockUnknownError("launch public marker or retained temp changed");
  const parsed = parseDirLockOwnerRecord(publicBytes);
  if (
    !parsed ||
    parsed.kind !== "a" ||
    parsed.pid !== claim.pid ||
    parsed.start !== claim.start ||
    parsed.nonce !== claim.nonce
  )
    throw new LockUnknownError("launch marker identity changed");
  if (
    !evidence.names.includes(`published.v3.${publicGeneration}`) &&
    !(
      allowUnrecordedLink &&
      evidence.names.every((name) => !name.startsWith("published.v3.")) &&
      tempGeneration === publicGeneration &&
      tempBytes?.equals(publicBytes)
    )
  )
    throw new LockUnknownError("launch file generation is not published");
  if (
    lockGeneration(ctx.parent) !==
    parseDirLockTransactionName(evidence.transactionName)?.generation
  )
    throw new LockUnknownError("launch parent generation changed");
}

function exactEmptyDirectory(parent: TDirectoryHandle, name: string): void {
  const child = childDirectory(parent, name);
  try {
    checkedNames(child, 0);
  } finally {
    close(child);
  }
  removeEmptyChild(parent, name);
}

function removePrivateEvidence(
  ctx: TLockControl,
  evidence: TLaunchEvidence,
): void {
  for (const name of evidence.names) {
    if (name === "plan.v3.json" || name === "plan.v3.tmp") {
      readRecord(evidence.transaction, name, 8192);
      unlinkChild(evidence.transaction, name);
    } else if (
      name === "handoff.v3" ||
      name.startsWith("published.v3.") ||
      name.startsWith("job.v3.")
    ) {
      exactEmptyDirectory(evidence.transaction, name);
    } else throw new LockUnknownError("unknown launch transaction entry");
  }
  removeEmptyChild(ctx.control, evidence.transactionName);
  const reservation = `b.v3.a.${encodeDirLockActor(evidence.claim)}`;
  if (childExists(ctx.control, reservation))
    exactEmptyDirectory(ctx.control, reservation);
}

function cleanupPublication(
  ctx: TLockControl,
  evidence: TLaunchEvidence,
  removePublic: boolean,
  allowUnrecordedLink = false,
): void {
  if (removePublic) {
    validatePublication(ctx, evidence, true, allowUnrecordedLink);
    unlinkChild(ctx.parent, ctx.base);
  }
  if (evidence.tempGeneration !== null) {
    if (
      fileGeneration(ctx.parent, evidence.tempName) !== evidence.tempGeneration
    )
      throw new LockUnknownError("launch temp generation changed");
    unlinkChild(ctx.parent, evidence.tempName);
  }
  removePrivateEvidence(ctx, evidence);
}

function recoverIncompletePlan(
  ctx: TLockControl,
  descriptor: NonNullable<ReturnType<typeof parseDirLockTransactionName>>,
): boolean {
  const transactionName = formatDirLockTransactionName(descriptor);
  const transaction = childDirectory(ctx.control, transactionName);
  try {
    if (childExists(transaction, "plan.v3.json")) return false;
    const names = checkedNames(transaction, 2);
    if (names.some((name) => name !== "plan.v3.tmp"))
      throw new LockUnknownError("incomplete launch plan has unknown evidence");
    if (
      descriptor.generation !== lockGeneration(ctx.parent) ||
      processIdentityStatus(descriptor.actor.pid, descriptor.actor.start) !==
        "dead" ||
      childExists(ctx.parent, ctx.base)
    )
      throw new LockUnknownError("incomplete launch plan cannot be recovered");
    const tempName = `${ctx.base}.${descriptor.actor.nonce}.tmp`;
    if (fileBytes(ctx.parent, tempName) !== null)
      unlinkChild(ctx.parent, tempName);
    if (names.includes("plan.v3.tmp")) {
      readRecord(transaction, "plan.v3.tmp", 8192);
      unlinkChild(transaction, "plan.v3.tmp");
    }
    removeEmptyChild(ctx.control, transactionName);
    const reservation = `b.v3.a.${encodeDirLockActor(descriptor.actor)}`;
    if (childExists(ctx.control, reservation))
      exactEmptyDirectory(ctx.control, reservation);
    return true;
  } finally {
    close(transaction);
  }
}

function recoverEndedLaunch(ctx: TLockControl, mode: TLaunchMode): void {
  const transactions = checkedNames(ctx.control, MAX_CONTROL)
    .map(parseDirLockTransactionName)
    .filter((entry) => entry?.kind === "a" && entry.operation === "p");
  if (transactions.length > 1)
    throw new LockUnknownError("multiple launch transactions");
  const descriptor = transactions[0];
  if (!descriptor) {
    if (childExists(ctx.parent, ctx.base))
      throw new LockUnknownError("tagged launch marker lacks a transaction");
    return;
  }
  if (recoverIncompletePlan(ctx, descriptor)) return;
  const evidence = transactionFor(ctx, descriptor.actor.nonce);
  if (!evidence) throw new LockUnknownError("launch transaction missing");
  try {
    const launcher = processIdentityStatus(
      evidence.claim.pid,
      evidence.claim.start,
    );
    if (launcher !== "dead")
      throw new LockUnknownError("launch helper remains live or uncertain");
    for (const name of evidence.names)
      if (name.startsWith("job.v3.")) {
        const actorToken =
          /^job\.v3\.([A-Za-z0-9_-]+)\.[0-9a-f]{16}\.[0-9a-f]{16}$/.exec(
            name,
          )?.[1];
        const actor = decodeDirLockActor(actorToken ?? "");
        if (!actor || processIdentityStatus(actor.pid, actor.start) !== "dead")
          throw new LockUnknownError("launch child remains live or uncertain");
      }
    if (evidence.publicBytes !== null) {
      // A crash can follow the link before its generation marker.
      validatePublication(ctx, evidence, true, true);
      if (mode === "mixed")
        throw new LockUnknownError(INCOMPLETE_LAUNCH_MESSAGE);
      cleanupPublication(ctx, evidence, true, true);
    } else cleanupPublication(ctx, evidence, false);
  } finally {
    close(evidence.transaction);
  }
}

function publication(ctx: TLockControl): {
  claim: TDirLockClaim;
  transactionName: string;
} {
  const start = processStartIdentity(process.pid);
  if (typeof start !== "string")
    throw new LockUnknownError("cannot identify launch helper");
  const claim: TDirLockClaim = {
    kind: "a",
    pid: process.pid,
    start,
    nonce: lockNonce(),
  };
  const generation = lockGeneration(ctx.parent);
  const reservation = `b.v3.a.${encodeDirLockActor(claim)}`;
  mkdirChild(ctx.control, reservation);
  const transactionName = formatDirLockTransactionName({
    kind: "a",
    operation: "p",
    actor: claim,
    generation,
  });
  try {
    mkdirChild(ctx.control, transactionName);
  } catch (error) {
    try {
      exactEmptyDirectory(ctx.control, reservation);
    } catch {
      /* Preserve the publication error and leave uncertain evidence. */
    }
    throw error;
  }
  const transaction = childDirectory(ctx.control, transactionName);
  const tempName = `${ctx.base}.${claim.nonce}.tmp`;
  let tempCreated = false;
  let createdGeneration: string | null = null;
  try {
    writeRecord(
      transaction,
      "plan.v3.tmp",
      "plan.v3.json",
      serializeDirLockPlan({
        version: 3,
        operation: "p",
        target: ctx.base,
        generation,
        basis: "absent",
        claim: null,
        ownerBytes: null,
        ageMtimeMs: null,
      }),
    );
    const bytes = Buffer.from(serializeDirLockOwnerRecord(claim));
    const temp = openChild(
      ctx.parent,
      tempName,
      posixOpenFlags().O_WRONLY |
        posixOpenFlags().O_CREAT |
        posixOpenFlags().O_EXCL,
      0o600,
    );
    tempCreated = true;
    let error: unknown;
    try {
      const created = statDescriptor(temp.fd);
      createdGeneration = `${created.dev.toString(16).padStart(16, "0")}.${created.ino.toString(16).padStart(16, "0")}`;
      writeFileSync(temp.fd, bytes);
      fsyncSync(temp.fd);
    } catch (failure) {
      error = failure;
    }
    try {
      close(temp);
    } catch (failure) {
      error ??= failure;
    }
    if (error !== undefined) throw error;
    if (
      !readRecord(ctx.parent, tempName, 1024).equals(bytes) ||
      lockGeneration(ctx.parent) !== generation
    )
      throw new LockUnknownError("launch temp verification failed");
    linkChild(ctx.parent, tempName, ctx.parent, ctx.base);
    const publicGeneration = fileGeneration(ctx.parent, ctx.base);
    if (
      !publicGeneration ||
      publicGeneration !== fileGeneration(ctx.parent, tempName) ||
      !readRecord(ctx.parent, ctx.base, 1024).equals(bytes)
    )
      throw new LockUnknownError("launch publication verification failed");
    mkdirChild(transaction, `published.v3.${publicGeneration}`);
    return { claim, transactionName };
  } catch (error) {
    try {
      const publicGeneration = fileGeneration(ctx.parent, ctx.base);
      const tempGeneration = fileGeneration(ctx.parent, tempName);
      if (
        publicGeneration === null ||
        (tempGeneration !== null && publicGeneration !== tempGeneration)
      ) {
        if (tempCreated && tempGeneration !== null) {
          if (tempGeneration !== createdGeneration)
            throw new LockUnknownError("launch temp changed after creation");
          fileBytes(ctx.parent, tempName);
          unlinkChild(ctx.parent, tempName);
        }
        if (!tempCreated && tempGeneration !== null)
          throw new LockUnknownError("launch temp ownership is uncertain");
        const names = checkedNames(transaction, 2);
        if (
          names.every(
            (name) => name === "plan.v3.json" || name === "plan.v3.tmp",
          )
        ) {
          for (const name of names) {
            readRecord(transaction, name, 8192);
            unlinkChild(transaction, name);
          }
          removeEmptyChild(ctx.control, transactionName);
          exactEmptyDirectory(ctx.control, reservation);
        }
      }
    } catch {
      /* Preserve the original error; later recovery sees retained evidence. */
    }
    throw error;
  } finally {
    close(transaction);
  }
}

function writeReady(path: string, code: number, nonce?: string): void {
  writeLockReply(path, code, nonce ?? null);
}

export async function runLaunchPublisher(
  markerPath: string,
  mode: TLaunchMode,
  readyPath: string,
  handoffWaitMs = READY_WAIT_MS,
): Promise<number> {
  if (
    process.platform === "win32" ||
    !isAbsolute(markerPath) ||
    !markerPath.endsWith(".launch.v3") ||
    (mode !== "mixed" && mode !== "new-only") ||
    !Number.isSafeInteger(handoffWaitMs) ||
    handoffWaitMs < 1 ||
    handoffWaitMs > READY_WAIT_MS
  )
    return 2;
  const ignoreHup = (): void => {};
  process.on("SIGHUP", ignoreHup);
  const ctx = openLockControl(markerPath, "a");
  try {
    const vendor = openLockControl(
      markerPath.replace(/\.launch\.v3$/, ".pid.d"),
      "v",
    );
    try {
      const checked = withLockGate(vendor, () => {
        inspectLegacyHold(vendor);
        return true;
      });
      if (checked !== true)
        throw new LockUnknownError("vendor metadata gate is busy");
    } finally {
      closeLockControl(vendor);
    }
    let published: { claim: TDirLockClaim; transactionName: string } | null =
      null;
    const deadline = performance.now() + 10_000;
    while (performance.now() < deadline && !published) {
      published = withLockGate(ctx, () => {
        inspectLegacyHold(ctx);
        recoverEndedLaunch(ctx, mode);
        if (childExists(ctx.parent, ctx.base))
          throw new LockUnknownError(INCOMPLETE_LAUNCH_MESSAGE);
        return publication(ctx);
      });
      if (!published) await pause(25);
    }
    if (!published) throw new LockUnknownError("launch gate unavailable");
    writeReady(readyPath, 0, published.claim.nonce);
    const handoffDeadline = performance.now() + handoffWaitMs;
    while (performance.now() < handoffDeadline) {
      const result = withLockGate(ctx, () => {
        const evidence = transactionFor(ctx, published.claim.nonce);
        if (!evidence)
          throw new LockUnknownError("launch transaction disappeared");
        try {
          if (!evidence.names.includes("handoff.v3")) return false;
          validatePublication(ctx, evidence);
          cleanupPublication(ctx, evidence, true);
          return true;
        } finally {
          close(evidence.transaction);
        }
      });
      if (result === true) return 0;
      await pause(25);
    }
    throw new LockUnknownError(INCOMPLETE_LAUNCH_MESSAGE);
  } catch (error) {
    const code = error instanceof LegacyLockError ? 73 : 74;
    try {
      writeReady(readyPath, code);
    } catch {
      /* The readiness file may already report success. */
    }
    process.stderr.write(
      `${error instanceof Error ? error.message : "launch helper failed"}\n`,
    );
    return code;
  } finally {
    closeLockControl(ctx);
    process.off("SIGHUP", ignoreHup);
  }
}

function childAction(
  markerPath: string,
  vendorLockPath: string,
  nonce: string,
  worker: TDirLockActor,
  phase: "associate" | "handoff",
  vendorClaim?: TDirLockOwner,
): void {
  if (
    !isAbsolute(markerPath) ||
    !isAbsolute(vendorLockPath) ||
    !/^[0-9a-f]{32}$/.test(nonce)
  )
    throw new TypeError("invalid launch association");
  const vendor = openDirectory(vendorLockPath);
  const ctx = openLockControl(markerPath, "a");
  try {
    const vendorGeneration = lockGeneration(vendor);
    const deadline = performance.now() + 10_000;
    do {
      const result = withLockGate(ctx, () => {
        inspectLegacyHold(ctx);
        const evidence = transactionFor(ctx, nonce);
        if (!evidence)
          throw new LockUnknownError("launch publication is missing");
        try {
          validatePublication(ctx, evidence);
          const association = `job.v3.${encodeDirLockActor(worker)}.${vendorGeneration}`;
          if (phase === "associate") {
            if (evidence.names.some((name) => name.startsWith("job.v3.")))
              throw new LockUnknownError("launch already has a child");
            mkdirChild(evidence.transaction, association);
            return true;
          }
          if (!evidence.names.includes(association) || !vendorClaim)
            throw new LockUnknownError("launch child association changed");
          const owner = parseDirLockOwnerRecord(
            readRecord(vendor, "owner.v3", 1024),
          );
          if (
            !owner ||
            owner.kind !== "v" ||
            owner.pid !== vendorClaim.pid ||
            owner.start !== vendorClaim.start ||
            owner.nonce !== vendorClaim.nonce
          )
            throw new LockUnknownError(
              "vendor owner is not the associated claim",
            );
          if (evidence.names.includes("handoff.v3"))
            throw new LockUnknownError("launch handoff already published");
          mkdirChild(evidence.transaction, "handoff.v3");
          return true;
        } finally {
          close(evidence.transaction);
        }
      });
      if (result === true) return;
      Bun.sleepSync(10);
    } while (performance.now() < deadline);
    throw new LockUnknownError("launch metadata gate is busy");
  } finally {
    closeLockControl(ctx);
    close(vendor);
  }
}

export function associateLaunchChild(
  markerPath: string,
  vendorLockPath: string,
  nonce: string,
  worker: TDirLockActor,
): void {
  childAction(markerPath, vendorLockPath, nonce, worker, "associate");
}
export function handoffLaunchChild(
  markerPath: string,
  vendorLockPath: string,
  nonce: string,
  worker: TDirLockActor,
  vendorClaim: TDirLockOwner,
): void {
  childAction(
    markerPath,
    vendorLockPath,
    nonce,
    worker,
    "handoff",
    vendorClaim,
  );
}
