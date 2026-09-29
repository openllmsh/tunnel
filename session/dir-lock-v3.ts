import { fsyncSync, writeFileSync } from "node:fs";
import type {
  TDirLockCodec,
  TDirLockOptions,
  TDirLockOwner,
  TDirLockRelease,
} from "./dir-lock";
import type { TLockControl, TLockKind } from "./dir-lock-control";
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
  openPinnedPath,
  readRecord,
  removeEmptyGeneration,
  removeLinkedRecordTemp,
  sameChildGeneration,
  withFileHandle,
  withLockGate,
  writeRecord,
} from "./dir-lock-control";
import type { TDirLockClaim, TDirLockPlan } from "./dir-lock-format";
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
  posixOpenFlags,
  removeEmptyChild,
  statDescriptor,
  unlinkChild,
} from "./dir-lock-fs";
import { inspectLegacyHold, namespaceSuffix } from "./dir-lock-legacy";
import { removeEndedVendorGroups } from "./dir-lock-vendor";
import { processIdentityStatus, processStartIdentity } from "./local-runtime";

const pendingReleases = new Map<string, TDirLockRelease>();
const activeClaims = new Set<string>();
const pendingCancellations = new Map<
  string,
  {
    path: string;
    claim: TDirLockClaim;
    transaction: string | undefined;
    worker: TDirLockOptions["worker"];
  }
>();
const emptyObservations = new Map<
  string,
  { generation: string; elapsed: number; wall: number }
>();

export const lockKindForCodec = (codec: TDirLockCodec): TLockKind => {
  if (codec.kind === "e" || codec.kind.includes("env-lock")) return "e";
  if (codec.kind === "u" || codec.kind.includes("update-lock")) return "u";
  if (codec.kind === "r" || codec.kind.includes("restore")) return "r";
  if (codec.kind === "v" || codec.kind.includes("vendor")) return "v";
  if (codec.kind === "a") return "a";
  throw new LockUnknownError("unsupported lock kind");
};
export type TDirLockObservation =
  | { readonly state: "absent" }
  | {
      readonly state: "valid";
      readonly claim: TDirLockClaim;
      readonly bytes: Buffer;
      readonly source: "published" | "temporary";
      readonly name: string;
    }
  | {
      readonly state: "unreadable";
      readonly reason: string;
      readonly code?: string;
    };
export const observePinnedOwner = (
  dir: TDirectoryHandle,
  kind: TLockKind,
): TDirLockObservation => {
  try {
    const names = checkedNames(dir, 512);
    if (names.some((name) => name.startsWith("steal.")))
      return { state: "unreadable", reason: "inside guard" };
    const ownerNames = names.filter((name) => name.startsWith("owner"));
    if (!ownerNames.length)
      return names.length
        ? { state: "unreadable", reason: "unknown directory entry" }
        : { state: "absent" };
    let found: Extract<TDirLockObservation, { state: "valid" }> | undefined;
    let fileGeneration: string | undefined;
    for (const name of names) {
      if (name !== "owner.v3" && !/^owner\.v3\.[0-9a-f]{32}\.tmp$/.test(name))
        return {
          state: "unreadable",
          reason: "unknown owner or directory entry",
        };
      const bytes = readRecord(dir, name, 1024);
      const owner = parseDirLockOwnerRecord(bytes);
      if (owner === null || owner.kind !== kind)
        return { state: "unreadable", reason: "invalid owner" };
      const file = openChild(dir, name, posixOpenFlags().O_RDONLY);
      let generation: string;
      try {
        const stat = statDescriptor(file.fd);
        generation = `${stat.dev}:${stat.ino}`;
      } finally {
        close(file);
      }
      if (
        found &&
        (!found.bytes.equals(bytes) || generation !== fileGeneration)
      )
        return { state: "unreadable", reason: "conflicting owner records" };
      fileGeneration = generation;
      const claim = {
        kind: owner.kind,
        pid: owner.pid,
        start: owner.start,
        nonce: owner.nonce,
      };
      if (!found || name === "owner.v3")
        found = {
          state: "valid",
          claim,
          bytes,
          source: name === "owner.v3" ? "published" : "temporary",
          name,
        };
    }
    return found ?? { state: "unreadable", reason: "owner observation failed" };
  } catch (error) {
    return {
      state: "unreadable",
      reason: "owner inspection failed",
      code: errorCode(error),
    };
  }
};
const actorStatus = (
  claim: TDirLockClaim,
  opts: TDirLockOptions,
): "alive" | "dead" | "unknown" =>
  processIdentityStatus(
    claim.pid,
    claim.start,
    opts.startIdentity,
    opts.legacyStartIdentity,
  );
const claimKey = (claim: TDirLockClaim): string =>
  `${claim.kind}.${encodeDirLockActor(claim)}`;
const terminalName = (claim: TDirLockClaim, released: boolean): string =>
  `${released ? "x" : "c"}.v3.${claimKey(claim)}`;
const reservationName = (claim: TDirLockClaim): string =>
  `b.v3.${claimKey(claim)}`;
const isTerminal = (ctx: TLockControl, claim: TDirLockClaim): boolean =>
  childExists(ctx.control, terminalName(claim, false)) ||
  childExists(ctx.control, terminalName(claim, true));
const mkdirRecord = (parent: TDirectoryHandle, name: string): void => {
  try {
    mkdirChild(parent, name);
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
    const dir = childDirectory(parent, name);
    try {
      if (checkedNames(dir, 0).length)
        throw new LockUnknownError("nonempty terminal record");
    } finally {
      close(dir);
    }
  }
};

const terminalize = (
  ctx: TLockControl,
  claim: TDirLockClaim,
  released: boolean,
): void => {
  if (!isTerminal(ctx, claim))
    mkdirRecord(ctx.control, terminalName(claim, released));
};
const retryCancellations = (ctx: TLockControl): void => {
  for (const [key, pending] of pendingCancellations) {
    if (pending.path !== ctx.path) continue;
    terminalize(ctx, pending.claim, false);
    if (pending.transaction && pending.worker) {
      const transaction = childDirectory(ctx.control, pending.transaction);
      try {
        if (
          ctx.kind === "v" &&
          childExists(transaction, "groups.v3") &&
          !removeEndedVendorGroups(transaction, true, pending.claim.start)
        )
          throw new LockUnknownError("vendor process group has not ended");
        const workerName = `worker.v3.${encodeDirLockActor(pending.worker)}`;
        if (childExists(transaction, workerName))
          removeEmptyChild(transaction, workerName);
        if (ctx.kind === "v" && childExists(transaction, "groups.v3"))
          removeEndedVendorGroups(transaction, false, pending.claim.start);
      } finally {
        close(transaction);
      }
    }
    pendingCancellations.delete(key);
  }
};
const registerPlan = (
  ctx: TLockControl,
  claim: TDirLockClaim,
  generation: string,
  operation: TDirLockPlan["operation"],
  basis: TDirLockPlan["basis"],
  bytes: Buffer | null,
): string => {
  const name = formatDirLockTransactionName({
    kind: claim.kind,
    operation,
    actor: claim,
    generation,
  });
  mkdirChild(ctx.control, name);
  const dir = childDirectory(ctx.control, name);
  try {
    writeRecord(
      dir,
      "plan.v3.tmp",
      "plan.v3.json",
      serializeDirLockPlan({
        version: 3,
        operation,
        target: ctx.base,
        generation,
        basis,
        claim: basis === "absent" ? null : claim,
        ownerBytes:
          basis === "absent" ? null : (bytes?.toString("base64url") ?? null),
        ageMtimeMs: null,
      }),
    );
  } finally {
    close(dir);
  }
  return name;
};
const removeTransaction = (ctx: TLockControl, name: string): void => {
  const dir = childDirectory(ctx.control, name);
  try {
    const names = checkedNames(dir, 8);
    if (
      names.some((entry) => entry !== "plan.v3.json" && entry !== "plan.v3.tmp")
    )
      throw new LockUnknownError(
        "unresolved transaction worker or destination",
      );
    for (const entry of names) {
      // Opening the record verifies its type before unlink.
      readRecord(dir, entry, 8192);
      unlinkChild(dir, entry);
    }
  } finally {
    close(dir);
  }
  removeEmptyChild(ctx.control, name);
};
const collectClaim = (ctx: TLockControl, claim: TDirLockClaim): void => {
  inspectLegacyHold(ctx);
  // Any selected residue can contain a copy or a producer.
  for (const name of checkedNames(ctx.parent, 4096))
    if (namespaceSuffix(ctx, name) !== null) return;
  const names = checkedNames(ctx.control, 512);
  for (const name of names) {
    const transaction = parseDirLockTransactionName(name);
    if (transaction && transaction.actor.nonce === claim.nonce) return;
  }
  for (const name of [
    terminalName(claim, false),
    terminalName(claim, true),
    reservationName(claim),
  ]) {
    if (!childExists(ctx.control, name)) continue;
    const dir = childDirectory(ctx.control, name);
    try {
      checkedNames(dir, 0);
    } finally {
      close(dir);
    }
    removeEmptyChild(ctx.control, name);
  }
};
const cleanupClaim = (
  ctx: TLockControl,
  dir: TDirectoryHandle,
  claim: TDirLockClaim,
  transactionName: string,
  generation: string,
): boolean => {
  inspectLegacyHold(ctx);
  if (!isTerminal(ctx, claim)) return false;
  const transaction = childDirectory(ctx.control, transactionName);
  try {
    const plan = parseDirLockPlan(
      readRecord(transaction, "plan.v3.json", 8192),
    );
    if (
      !plan ||
      plan.generation !== generation ||
      (plan.operation !== "p" && plan.claim?.nonce !== claim.nonce) ||
      plan.target !== ctx.base ||
      lockGeneration(dir) !== generation
    )
      return false;
    removeLinkedRecordTemp(transaction, "plan.v3.tmp", "plan.v3.json", 8192);
    if (checkedNames(transaction, 8).some((name) => name !== "plan.v3.json"))
      return false;
    const names = checkedNames(dir, 512);
    if (
      names.some(
        (name) => name !== "owner.v3" && name !== `owner.v3.${claim.nonce}.tmp`,
      )
    )
      return false;
    if (names.includes("owner.v3")) {
      const bytes = readRecord(dir, "owner.v3", 1024);
      if (
        bytes.toString("base64url") !==
        (plan.operation === "p"
          ? Buffer.from(serializeDirLockOwnerRecord(claim)).toString(
              "base64url",
            )
          : plan.ownerBytes)
      )
        return false;
      unlinkChild(dir, "owner.v3");
    }
    const temp = `owner.v3.${claim.nonce}.tmp`;
    if (names.includes(temp)) {
      // The exact publication transaction authorizes its partial regular temp.
      readRecord(dir, temp, 1024);
      unlinkChild(dir, temp);
    }
  } finally {
    close(transaction);
  }
  if (!removeEmptyGeneration(ctx.parent, ctx.base, generation)) return false;
  removeTransaction(ctx, transactionName);
  collectClaim(ctx, claim);
  return true;
};
const recoverControl = (
  ctx: TLockControl,
  opts: TDirLockOptions,
  deadline: number,
): void => {
  const now = opts.elapsedNow ?? opts.now ?? performance.now.bind(performance);
  let work = 0;
  const names = checkedNames(ctx.control, 512);
  for (const name of names) {
    if (++work > 32 || now() > deadline) return;
    const tx = parseDirLockTransactionName(name);
    if (tx === null) continue;
    const claim: TDirLockClaim = { kind: tx.kind, ...tx.actor };
    if (
      tx.kind !== ctx.kind ||
      (!isTerminal(ctx, claim) && actorStatus(claim, opts) !== "dead")
    )
      continue;
    const transaction = childDirectory(ctx.control, name);
    let plan: TDirLockPlan | null = null;
    try {
      const entries = checkedNames(transaction, 8);
      let workerHeld = false;
      for (const entry of entries) {
        if (entry === "plan.v3.tmp" || entry === "plan.v3.json") continue;
        if (ctx.kind === "v" && entry === "groups.v3") continue;
        const worker = entry.startsWith("worker.v3.")
          ? decodeDirLockActor(entry.slice(10))
          : null;
        if (
          !worker ||
          processIdentityStatus(
            worker.pid,
            worker.start,
            opts.startIdentity,
            opts.legacyStartIdentity,
          ) !== "dead"
        ) {
          workerHeld = true;
          break;
        }
      }
      if (workerHeld) continue;
      if (
        ctx.kind === "v" &&
        entries.some(
          (entry) => entry.startsWith("worker.v3.") || entry === "groups.v3",
        ) &&
        !removeEndedVendorGroups(transaction, true, claim.start)
      )
        continue;
      for (const entry of entries.filter((entry) =>
        entry.startsWith("worker.v3."),
      )) {
        const workerDir = childDirectory(transaction, entry);
        try {
          checkedNames(workerDir, 0);
        } finally {
          close(workerDir);
        }
        removeEmptyChild(transaction, entry);
      }
      if (ctx.kind === "v" && entries.includes("groups.v3"))
        removeEndedVendorGroups(transaction, false, claim.start);
      if (entries.includes("plan.v3.json")) {
        plan = parseDirLockPlan(readRecord(transaction, "plan.v3.json", 8192));
        if (plan === null)
          throw new LockUnknownError("invalid completed transaction plan");
      }
    } finally {
      close(transaction);
    }
    if (plan === null) {
      // An incomplete plan authorized no lock-content mutation.
      if (sameChildGeneration(ctx.parent, ctx.base, tx.generation)) {
        const empty = childDirectory(ctx.parent, ctx.base);
        try {
          if (checkedNames(empty, 512).length === 0)
            removeEmptyGeneration(ctx.parent, ctx.base, tx.generation);
        } finally {
          close(empty);
        }
      }
      removeTransaction(ctx, name);
      collectClaim(ctx, claim);
      continue;
    }
    if (
      plan.target !== ctx.base ||
      plan.generation !== tx.generation ||
      (plan.operation !== "p" && plan.claim?.nonce !== claim.nonce)
    )
      throw new LockUnknownError("transaction association failed");
    terminalize(ctx, claim, false);
    if (!childExists(ctx.parent, ctx.base)) {
      removeTransaction(ctx, name);
      collectClaim(ctx, claim);
      continue;
    }
    if (!sameChildGeneration(ctx.parent, ctx.base, tx.generation)) continue;
    const dir = childDirectory(ctx.parent, ctx.base);
    try {
      cleanupClaim(ctx, dir, claim, name, tx.generation);
    } finally {
      close(dir);
    }
  }
  for (const name of checkedNames(ctx.control, 512)) {
    if (++work > 32 || now() > deadline) return;
    const match = /^[bcx]\.v3\.([eurva])\.(.+)$/.exec(name);
    if (!match) continue;
    const actor = decodeDirLockActor(match[2] ?? "");
    if (!actor || match[1] !== ctx.kind)
      throw new LockUnknownError("invalid control record");
    const claim: TDirLockClaim = { kind: ctx.kind, ...actor };
    if (actorStatus(claim, opts) === "dead") collectClaim(ctx, claim);
  }
};
type TAttemptClock = {
  reentered?: boolean;
  readonly elapsed: () => number;
  readonly wall: () => number;
  readonly deadline: number;
  readonly startElapsed: number;
  readonly startWall: number;
};
const clockFor = (opts: TDirLockOptions): TAttemptClock => {
  if (
    !Number.isFinite(opts.waitMs) ||
    opts.waitMs < 0 ||
    !Number.isFinite(opts.reclaimMs) ||
    opts.reclaimMs < 0 ||
    (opts.pollMs !== undefined &&
      (!Number.isFinite(opts.pollMs) || opts.pollMs <= 0))
  )
    throw new LockUnknownError("invalid lock budget");
  const elapsed =
    opts.elapsedNow ?? opts.now ?? performance.now.bind(performance);
  const wall = opts.wallNow ?? Date.now;
  const startElapsed = elapsed();
  return {
    elapsed,
    wall,
    startElapsed,
    startWall: wall(),
    deadline: startElapsed + Math.max(0, opts.waitMs),
  };
};
const acquireAttempt = (
  ctx: TLockControl,
  opts: TDirLockOptions,
  clock: TAttemptClock,
): TDirLockRelease | null =>
  withLockGate(ctx, () => {
    retryCancellations(ctx);
    inspectLegacyHold(ctx);
    recoverControl(ctx, opts, clock.deadline);
    inspectLegacyHold(ctx);
    const controls = checkedNames(ctx.control, 512);
    for (const name of controls) {
      if (name === "meta.v3.lock") continue;
      const tx = parseDirLockTransactionName(name);
      if (tx && tx.kind === ctx.kind) continue;
      const simple = /^[bcx]\.v3\.([eurva])\.(.+)$/.exec(name);
      if (
        !simple ||
        simple[1] !== ctx.kind ||
        !decodeDirLockActor(simple[2] ?? "")
      )
        return null;
      const record = childDirectory(ctx.control, name);
      try {
        checkedNames(record, 0);
      } finally {
        close(record);
      }
    }
    if (
      pendingCancellations.size >= 64 ||
      controls.filter((name) => name.startsWith("b.v3.")).length >= 64 ||
      controls.filter((name) => /^[cx]\.v3\./.test(name)).length >= 64 ||
      controls.filter((name) => name.startsWith("t.v3.")).length >= 256
    )
      return null;
    if (childExists(ctx.parent, ctx.base)) {
      const dir = childDirectory(ctx.parent, ctx.base);
      try {
        const owner = observePinnedOwner(dir, ctx.kind);
        if (owner.state === "unreadable") return null;
        if (owner.state === "valid") {
          if (activeClaims.has(encodeDirLockActor(owner.claim))) {
            clock.reentered = true;
            return null;
          }
          // Published owners need their exact publication transaction.
          const generation = lockGeneration(dir);
          const transaction = formatDirLockTransactionName({
            kind: ctx.kind,
            operation: "p",
            actor: owner.claim,
            generation,
          });
          if (
            !controls.includes(transaction) ||
            (!isTerminal(ctx, owner.claim) &&
              actorStatus(owner.claim, opts) !== "dead")
          )
            return null;
          terminalize(ctx, owner.claim, false);
          if (!cleanupClaim(ctx, dir, owner.claim, transaction, generation))
            return null;
        } else {
          if (controls.some((name) => name.startsWith("t.v3."))) return null;
          const grace = opts.ownerlessMs ?? opts.reclaimMs;
          const generation = lockGeneration(dir);
          let observed = emptyObservations.get(ctx.path);
          if (
            observed &&
            (observed.generation !== generation ||
              Math.abs(
                clock.wall() -
                  observed.wall -
                  (clock.elapsed() - observed.elapsed),
              ) > 1000)
          ) {
            emptyObservations.delete(ctx.path);
            observed = undefined;
          }
          if (!observed) {
            if (emptyObservations.size >= 64) return null;
            observed = {
              generation,
              elapsed: clock.elapsed(),
              wall: clock.wall(),
            };
            emptyObservations.set(ctx.path, observed);
          }
          const wallAge = clock.wall() - Number(statDescriptor(dir.fd).mtimeMs);
          if (wallAge < grace || clock.elapsed() - observed.elapsed < grace)
            return null;
          if (!removeEmptyGeneration(ctx.parent, ctx.base, generation))
            return null;
          emptyObservations.delete(ctx.path);
        }
      } finally {
        close(dir);
      }
    }
    // A new unknown sibling blocks this domain.
    if (
      checkedNames(ctx.parent, 4096).some(
        (name) => namespaceSuffix(ctx, name) !== null,
      )
    )
      return null;
    if (opts.waitMs > 0 && clock.elapsed() > clock.deadline) return null;
    const start = (opts.ownerStartIdentity ?? processStartIdentity)(
      process.pid,
    );
    if (typeof start !== "string") return null;
    const claim: TDirLockClaim = {
      kind: ctx.kind,
      pid: process.pid,
      start,
      nonce: lockNonce(),
    };
    const ownerBytes = Buffer.from(serializeDirLockOwnerRecord(claim));
    mkdirChild(ctx.control, reservationName(claim));
    let dir: TDirectoryHandle | undefined;
    let transaction: string | undefined;
    let generation: string | undefined;
    let granted = false;
    try {
      opts.onStep?.("before-mkdir", ctx.path);
      mkdirChild(ctx.parent, ctx.base);
      dir = childDirectory(ctx.parent, ctx.base);
      generation = lockGeneration(dir);
      opts.onStep?.("after-mkdir", ctx.path, claim);
      transaction = formatDirLockTransactionName({
        kind: claim.kind,
        operation: "p",
        actor: claim,
        generation,
      });
      registerPlan(ctx, claim, generation, "p", "absent", ownerBytes);
      if (opts.worker) {
        const planDir = childDirectory(ctx.control, transaction);
        try {
          if (ctx.kind === "v") mkdirRecord(planDir, "groups.v3");
          mkdirRecord(planDir, `worker.v3.${encodeDirLockActor(opts.worker)}`);
        } finally {
          close(planDir);
        }
      }
      inspectLegacyHold(ctx);
      if (observePinnedOwner(dir, ctx.kind).state !== "absent")
        throw new LockUnknownError("publication directory changed");
      const temp = `owner.v3.${claim.nonce}.tmp`;
      const fd = openChild(
        dir,
        temp,
        posixOpenFlags().O_WRONLY |
          posixOpenFlags().O_CREAT |
          posixOpenFlags().O_EXCL,
        0o600,
      );
      withFileHandle(fd, () => {
        writeFileSync(fd.fd, ownerBytes);
        fsyncSync(fd.fd);
      });
      if (!readRecord(dir, temp, 1024).equals(ownerBytes))
        throw new LockUnknownError("owner verification failed");
      opts.onStep?.("before-publish", ctx.path);
      inspectLegacyHold(ctx);
      if (!sameChildGeneration(ctx.parent, ctx.base, generation))
        throw new LockUnknownError("lock generation changed");
      linkChild(dir, temp, dir, "owner.v3");
      unlinkChild(dir, temp);
      opts.onStep?.("after-publish", ctx.path);
      inspectLegacyHold(ctx);
      const owner = observePinnedOwner(dir, ctx.kind);
      if (
        (opts.waitMs > 0 && clock.elapsed() > clock.deadline) ||
        !sameChildGeneration(ctx.parent, ctx.base, generation) ||
        owner.state !== "valid" ||
        !owner.bytes.equals(ownerBytes) ||
        isTerminal(ctx, claim)
      )
        throw new LockUnknownError("lock grant validation failed");
      if (
        !childExists(ctx.control, reservationName(claim)) ||
        !childExists(ctx.control, transaction)
      )
        throw new LockUnknownError("publication evidence changed");
      opts.onStep?.("before-grant", ctx.path, claim);
      granted = true;
      const activeClaim = encodeDirLockActor(claim);
      activeClaims.add(activeClaim);
      const capturedDir = dir;
      const capturedTransaction = transaction;
      const capturedGeneration = generation;
      let done = false;
      const release = (): void => {
        if (done) return;
        activeClaims.delete(activeClaim);
        let terminalPublished = false;
        try {
          const start = performance.now();
          const wait = new Int32Array(new SharedArrayBuffer(4));
          for (let attempt = 0; attempt <= 100; attempt++) {
            const released = withLockGate(ctx, () => {
              if (opts.worker) {
                const planDir = childDirectory(
                  ctx.control,
                  capturedTransaction,
                );
                try {
                  if (
                    ctx.kind === "v" &&
                    childExists(planDir, "groups.v3") &&
                    !removeEndedVendorGroups(planDir, true, claim.start)
                  )
                    throw new LockUnknownError(
                      "vendor process group has not ended",
                    );
                  removeEmptyChild(
                    planDir,
                    `worker.v3.${encodeDirLockActor(opts.worker)}`,
                  );
                  if (ctx.kind === "v" && childExists(planDir, "groups.v3"))
                    removeEndedVendorGroups(planDir, false, claim.start);
                } finally {
                  close(planDir);
                }
              }
              terminalize(ctx, claim, true);
              terminalPublished = true;
              opts.onStep?.("before-release", ctx.path);
              cleanupClaim(
                ctx,
                capturedDir,
                claim,
                capturedTransaction,
                capturedGeneration,
              );
              return true;
            });
            if (released !== null) break;
            const elapsed = performance.now() - start;
            if (
              !Number.isFinite(elapsed) ||
              elapsed < 0 ||
              elapsed >= 1000 ||
              attempt === 100
            )
              throw new LockUnknownError(
                "metadata gate is busy during release",
              );
            Atomics.wait(wait, 0, 0, Math.min(10, 1000 - elapsed));
          }
        } finally {
          if (terminalPublished) {
            done = true;
            pendingReleases.delete(ctx.path);
            close(capturedDir);
            closeLockControl(ctx);
          } else pendingReleases.set(ctx.path, release);
        }
      };
      return release;
    } catch (error) {
      const pendingKey = `${ctx.path}\0${claim.nonce}`;
      pendingCancellations.set(pendingKey, {
        path: ctx.path,
        claim,
        transaction,
        worker: opts.worker,
      });
      try {
        terminalize(ctx, claim, false);
        if (transaction && opts.worker) {
          const planDir = childDirectory(ctx.control, transaction);
          try {
            if (
              ctx.kind === "v" &&
              childExists(planDir, "groups.v3") &&
              !removeEndedVendorGroups(planDir, true, claim.start)
            )
              throw new LockUnknownError("vendor process group has not ended");
            const worker = `worker.v3.${encodeDirLockActor(opts.worker)}`;
            if (childExists(planDir, worker)) removeEmptyChild(planDir, worker);
            if (ctx.kind === "v" && childExists(planDir, "groups.v3"))
              removeEndedVendorGroups(planDir, false, claim.start);
          } finally {
            close(planDir);
          }
        }
        pendingCancellations.delete(pendingKey);
        if (dir && transaction && generation)
          cleanupClaim(ctx, dir, claim, transaction, generation);
        else if (dir && generation) {
          inspectLegacyHold(ctx);
          if (removeEmptyGeneration(ctx.parent, ctx.base, generation))
            collectClaim(ctx, claim);
        } else if (!dir) collectClaim(ctx, claim);
      } catch {
        /* Keep the reservation and transaction for recovery. */
      }
      if (error instanceof LegacyLockError || opts.propagatePublishErrors)
        throw error;
      return null;
    } finally {
      if (!granted && dir) close(dir);
    }
  });
export const acquireDirLockV3Sync = (
  path: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): TDirLockRelease | null => {
  const clock = clockFor(opts);
  pendingReleases.get(path)?.();
  if (pendingReleases.size >= 64) return null;
  const ctx = openLockControl(path, lockKindForCodec(codec));
  let release: TDirLockRelease | null = null;
  const poll = Math.max(1, opts.pollMs ?? 10);
  const attempts = 1 + Math.ceil(Math.max(0, opts.waitMs) / poll);
  const wait = new Int32Array(new SharedArrayBuffer(4));
  let publishError: unknown;
  try {
    for (let index = 0; index < attempts; index++) {
      try {
        release = acquireAttempt(ctx, opts, clock);
      } catch (error) {
        if (!["EIO", "ENOSPC"].includes(errorCode(error) ?? "")) throw error;
        publishError ??= error;
      }
      if (release) return release;
      if (clock.reentered) return null;
      const remaining = clock.deadline - clock.elapsed();
      if (remaining <= 0) break;
      Atomics.wait(wait, 0, 0, Math.min(poll, remaining));
    }
    if (publishError !== undefined) throw publishError;
    return null;
  } finally {
    if (!release) closeLockControl(ctx);
  }
};
export const acquireDirLockV3 = async (
  path: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): Promise<TDirLockRelease | null> => {
  const clock = clockFor(opts);
  pendingReleases.get(path)?.();
  if (pendingReleases.size >= 64) return null;
  const ctx = openLockControl(path, lockKindForCodec(codec));
  let release: TDirLockRelease | null = null;
  const poll = Math.max(1, opts.pollMs ?? 50);
  const attempts = 1 + Math.ceil(Math.max(0, opts.waitMs) / poll);
  let publishError: unknown;
  try {
    for (let index = 0; index < attempts; index++) {
      try {
        release = acquireAttempt(ctx, opts, clock);
      } catch (error) {
        if (!["EIO", "ENOSPC"].includes(errorCode(error) ?? "")) throw error;
        publishError ??= error;
      }
      if (release) return release;
      if (clock.reentered) return null;
      const remaining = clock.deadline - clock.elapsed();
      if (remaining <= 0) break;
      await (
        opts.sleep ??
        ((ms: number): Promise<void> =>
          new Promise((resolve) => setTimeout(resolve, ms)))
      )(Math.min(poll, remaining));
    }
    if (publishError !== undefined) throw publishError;
    return null;
  } finally {
    if (!release) closeLockControl(ctx);
  }
};
export const inspectDirLockV3 = (
  path: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): void => {
  const clock = clockFor(opts);
  const ctx = openLockControl(path, lockKindForCodec(codec));
  try {
    withLockGate(ctx, () => {
      inspectLegacyHold(ctx);
      recoverControl(ctx, opts, clock.deadline);
    });
  } finally {
    closeLockControl(ctx);
  }
};
/** Read the published owner without creating control state. */
export const readDirLockV3Owner = (
  path: string,
  codec: TDirLockCodec,
): TDirLockOwner | null => {
  let dir: TDirectoryHandle;
  try {
    dir = openPinnedPath(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
  try {
    const observation = observePinnedOwner(dir, lockKindForCodec(codec));
    return observation.state === "valid" ? observation.claim : null;
  } finally {
    close(dir);
  }
};

export const v3DirLockCodec = (kind: TLockKind): TDirLockCodec => {
  const observe = (path: string): TDirLockObservation => {
    let dir: TDirectoryHandle | undefined;
    try {
      dir = openPinnedPath(path);
      return observePinnedOwner(dir, kind);
    } catch (error) {
      return {
        state: "unreadable",
        reason: "lock directory cannot be inspected",
        code: errorCode(error),
      };
    } finally {
      if (dir) close(dir);
    }
  };
  return {
    kind,
    ownerFile: "owner.v3",
    markerInsideDir: true,
    observeOwner: observe,
    readOwner: (path: string): TDirLockOwner | null => {
      const result = observe(path);
      return result.state === "valid" ? result.claim : null;
    },
    parseOwner: (bytes: string): TDirLockOwner | null =>
      parseDirLockOwnerRecord(bytes),
    serializeOwner: (owner: TDirLockOwner): string =>
      serializeDirLockOwnerRecord({ ...owner, kind }),
  };
};
