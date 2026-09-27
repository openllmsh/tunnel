/**
 * Cross-process exclusive lock for the CLI binary swap region.
 *
 * TWO writers converge on the same `openllm` binary: the daemon's background
 * CLI converger (`packages/daemon/src/cli-self-update.ts`) and a manual
 * `openllm self-update` (`packages/cli/src/self-update.ts`). A process-local
 * `updating` flag can't serialize them — last-writer-wins could interleave
 * probe → backup → rename → state-marker so `<dest>.prev` ends up unrelated
 * to the final binary and `state.json` records the OTHER update. This lock is
 * shared by both binaries (the one place a common implementation can live)
 * and covers exactly that swap region; the download itself stays outside it.
 *
 * Implementation (ownership-proven, never check-then-delete):
 *
 *   - `mkdir(lockDir)` is the atomic acquire (EEXIST = held).
 *   - The holder publishes `owner.json` INSIDE the dir — `{kind, pid, start,
 *     nonce}` — atomically (pid/nonce-named temp + rename). `start` is the
 *     exact process-start identity (`processStartIdentity`), so a reused PID
 *     can't masquerade as the dead process it replaced; `nonce` is a random
 *     128-bit ownership token that makes every later step verifiable.
 *   - A record is PROVEN-LIVE only when its pid is alive AND the recorded
 *     start identity matches the live process at that pid — it is never
 *     evicted, however old the dir is. A record is STALE when its pid is
 *     confirmed dead or provably a DIFFERENT process (PID reuse — the
 *     recorded start identity no longer matches). Anything else — an
 *     unreadable or unmarked dir, a live pid recorded with an empty start
 *     (no identity to compare), or an inconclusive probe over a live pid —
 *     is UNPROVEN: HELD, but reclaimable once the dir has shown no complete
 *     owner for `UPDATE_LOCK_RECLAIM_MS`, so a crash between mkdir and
 *     publish (or a holder that can never prove its start) can't wedge
 *     every later writer forever. A lone `owner.json.<nonce>.tmp` still
 *     carries a readable record (a holder that died mid-publish) and is
 *     evaluated the same way.
 *   - Steal = a sibling `<lockDir>.stealing-<pid>-<nonce>` MARKER is created
 *     first and stays up for the whole transaction, then an atomic
 *     `rename(lockDir, quarantine)` — only ONE racer wins the rename — then
 *     RE-VALIDATE inside quarantine: still-stale or unproven-past-the-bound
 *     → delete; a live owner (released + re-acquired between our read and
 *     the rename, or a publish that landed mid-race — its fresh record
 *     mtime is still inside the bound) → move back with a no-replace
 *     rename. The marker is what makes the race safe (FSS-14): while it is
 *     up, a lock dir that vanished under the rename is provably mid-steal,
 *     and an acquirer that lands an mkdir in the gap sees the marker and
 *     undoes its own empty dir instead of becoming a second holder.
 *   - Leftover markers/quarantine dirs from a crashed stealer are adjudicated
 *     on every acquire pass: a live marker is honored, a dead-pid or aged
 *     marker is removed, and a stranded quarantine dir is re-validated —
 *     proven-live restores no-replace, stale deletes.
 *   - Release/cleanup = rename `lockDir` to a unique quarantine name FIRST,
 *     then verify the owner nonce inside quarantine matches ours before
 *     deleting — if it does not, move the dir back (no-replace) and do
 *     nothing else. The old owner can NEVER delete the new owner's lock.
 *   - Re-entry (same process acquiring twice) requires pid AND start AND
 *     nonce to match — each acquisition mints a fresh nonce, so a second
 *     acquire always fails fast instead of self-deadlocking.
 *
 * No flock dependency: this must work identically on macOS and Linux under
 * both `bun` and the compiled binaries.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import type { TProcessStartIdentityReader } from "./session/local-runtime";
import {
  processIdentityStatus,
  processStartIdentity,
} from "./session/local-runtime";

/** The lock dir sits next to the binary being swapped: `<dest>.update.lock`. */
export const updateLockDirFor = (destPath: string): string =>
  `${destPath}.update.lock`;

const OWNER_FILE = "owner.json";
const OWNER_KIND = "openllm-update-lock/v1";

/** Default time an acquirer waits for a live holder before giving up. */
export const UPDATE_LOCK_WAIT_MS = 30_000;
/**
 * Bounded reclaim horizon. A dir whose only claim is UNPROVEN — unmarked,
 * unreadable, or a record that can neither be convicted nor proven live —
 * stays held until this long after its last evidence of a complete owner
 * (dir mtime / owner record publish time). A PROVEN-live owner is never
 * reclaimed regardless of age.
 */
export const UPDATE_LOCK_RECLAIM_MS = 10 * 60_000;
const POLL_MS = 250;

/**
 * The ownership record published in `owner.json`. `start` is the process-start
 * identity {@link processStartIdentity} reports for `pid` ("" when the owner
 * couldn't probe itself — such a record can neither convict on PID reuse nor
 * prove a live pid is the same process, so it lands in UNPROVEN, never
 * proven-live). `nonce` is the ownership token releases/steals verify.
 */
type TOwnerRecord = {
  readonly kind: typeof OWNER_KIND;
  readonly pid: number;
  readonly start: string;
  readonly nonce: string;
};

export type TUpdateLockOptions = {
  /** How long to wait for a live holder before giving up (`null` result). */
  readonly waitMs?: number;
  /** Injectable clock for tests. */
  readonly now?: () => number;
  /** Injectable sleep for tests. */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Injectable liveness probe for tests. */
  readonly pidAlive?: (pid: number) => boolean;
  /** Injectable start-identity probe for tests (PID-reuse detection). */
  readonly startIdentity?: TProcessStartIdentityReader;
};

/** The release function returned on a successful acquire. */
export type TUpdateLockRelease = () => void;

/** True when `pid` refers to a live process. `process.kill(pid, 0)`: ESRCH =
 *  dead, EPERM = alive but owned by another user. Anything else conservatively
 *  counts as alive so an exotic failure can't trigger a steal. */
const defaultPidAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
};

/** 128-bit random ownership token — fresh per acquisition attempt. */
const newNonce = (): string => randomBytes(16).toString("hex");

/** Unique quarantine name for one steal/release transaction. */
const quarantinePath = (lockDir: string, tag: string, nonce: string): string =>
  `${lockDir}.${tag}-${process.pid}-${nonce}`;

/**
 * A sibling dir named `<lock>.stealing-<pid>-<nonce>` marks a steal in
 * flight (FSS-14). The stealer creates it BEFORE the quarantine rename and
 * keeps it until the move-back-or-delete decision is final, so the name gap
 * between `rename(lockDir, quarantine)` and any restore can never admit a
 * second logical owner: an acquirer whose mkdir lands in the gap sees the
 * marker and backs out of its own just-made empty dir.
 */
const stealMarkerName = (lockDir: string, nonce: string): string =>
  `${lockDir}.stealing-${process.pid}-${nonce}`;

/** The creator pid embedded in a `<lock>.stealing-<pid>-<nonce>` marker. */
const stealMarkerPid = (lockDir: string, name: string): number | null => {
  const prefix = `${basename(lockDir)}.stealing-`;
  if (!name.startsWith(prefix)) return null;
  const pid = Number.parseInt(
    name.slice(prefix.length).split("-")[0] ?? "",
    10,
  );
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
};

/** True while a sibling `.stealing-*` marker exists — a steal is in flight
 *  and an acquirer must not claim the freed name. */
const stealInFlight = (lockDir: string): boolean => {
  let names: string[];
  try {
    names = readdirSync(dirname(lockDir));
  } catch {
    return false;
  }
  return names.some((name) => stealMarkerPid(lockDir, name) !== null);
};

/** Test seam: runs inside a steal AFTER the quarantine rename, before the
 *  re-validation — the exact window FSS-14 exploits. */
let stealGapHookForTests: ((lockDir: string) => void) | null = null;
export const setUpdateLockStealGapHookForTests = (
  hook: ((lockDir: string) => void) | null,
): void => {
  stealGapHookForTests = hook;
};

/** Test seam: runs inside a quarantine restore BEFORE the claim on `to` —
 *  the exact check-then-move gap a racing claim used to exploit. */
let moveBackGapHookForTests: ((from: string, to: string) => void) | null = null;
export const setUpdateLockMoveBackGapHookForTests = (
  hook: ((from: string, to: string) => void) | null,
): void => {
  moveBackGapHookForTests = hook;
};

const coerceOwner = (v: unknown): TOwnerRecord | null => {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Partial<TOwnerRecord>;
  if (
    o.kind !== OWNER_KIND ||
    !Number.isSafeInteger(o.pid) ||
    (o.pid as number) <= 0 ||
    typeof o.start !== "string" ||
    typeof o.nonce !== "string" ||
    o.nonce.length === 0
  ) {
    return null;
  }
  return {
    kind: OWNER_KIND,
    pid: o.pid as number,
    start: o.start,
    nonce: o.nonce,
  };
};

const readOwnerFile = (path: string): TOwnerRecord | null => {
  try {
    return coerceOwner(JSON.parse(readFileSync(path, "utf-8")));
  } catch {
    return null;
  }
};

/** Valid un-published owner records (`owner.json.<nonce>.tmp`) inside a dir. */
const readTmpOwners = (dir: string): TOwnerRecord[] => {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: TOwnerRecord[] = [];
  for (const name of names) {
    if (!name.startsWith(`${OWNER_FILE}.`) || !name.endsWith(".tmp")) continue;
    const owner = readOwnerFile(join(dir, name));
    if (owner !== null) out.push(owner);
  }
  return out;
};

/**
 * The ownership record a lock dir currently proves — `owner.json` when
 * published, else the SINGLE readable publish-temp record (a holder that died
 * mid-publish is still identifiable + stealable). Anything else — an empty
 * dir, corrupt JSON, multiple conflicting records — is UNMARKED: still HELD
 * (a mid-setup holder is never evicted outright), but bounded — reclaimable
 * once the dir has shown no complete owner for `UPDATE_LOCK_RECLAIM_MS`.
 */
const readOwner = (dir: string): TOwnerRecord | null => {
  const published = readOwnerFile(join(dir, OWNER_FILE));
  if (published !== null) return published;
  const tmps = readTmpOwners(dir);
  return tmps.length === 1 ? (tmps[0] ?? null) : null;
};

/**
 * Three-way verdict for a recorded owner:
 *
 *   - `proven-live` — pid alive AND the recorded start identity matches the
 *     live process at that pid. A record with an EMPTY `start` can never
 *     reach this verdict: there is no identity to compare, so liveness alone
 *     must not prove a live pid — a reused pid would otherwise inherit the
 *     dead owner's lock forever. Never reclaimed, whatever the dir's age.
 *   - `stale` — provably gone: confirmed dead, the probe is inconclusive AND
 *     liveness says dead, or the pid is alive but belongs to a DIFFERENT
 *     process (PID reuse — the exact start identity no longer matches the
 *     recorded one).
 *   - `unproven` — can neither be convicted nor proven: a live pid behind an
 *     inconclusive probe, or a live pid against an empty recorded start.
 *     HELD, but eligible for the bounded reclaim — never promoted to
 *     proven-live by liveness alone.
 */
const classifyOwner = (
  owner: TOwnerRecord,
  probes: {
    readonly pidAlive: (pid: number) => boolean;
    readonly startIdentity: TProcessStartIdentityReader;
  },
): "stale" | "proven-live" | "unproven" => {
  if (owner.start === "") {
    // No recorded identity: liveness alone can only ever prove DEAD — a
    // live pid with nothing to compare stays unproven so a reused pid can
    // never inherit the lock.
    return probes.pidAlive(owner.pid) ? "unproven" : "stale";
  }
  // processIdentityStatus bridges the RT-1 format change: an old `ps lstart`
  // record is re-probed with the legacy reader instead of being convicted
  // by a raw string mismatch against the boot-scoped identity.
  const status = processIdentityStatus(
    owner.pid,
    owner.start,
    probes.startIdentity,
  );
  if (status === "alive") return "proven-live";
  if (status === "dead") return "stale";
  return probes.pidAlive(owner.pid) ? "unproven" : "stale";
};

/**
 * The newest mtime among `owner.json` and any `owner.json.<nonce>.tmp`
 * publish temps — the last time the dir gained (or nearly gained) a complete
 * owner record. Write-then-rename keeps the write's mtime, so a published
 * record's mtime IS its publish time.
 */
const ownerRecordTimeMs = (dir: string): number | null => {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  let latest: number | null = null;
  for (const name of names) {
    if (
      name !== OWNER_FILE &&
      !(name.startsWith(`${OWNER_FILE}.`) && name.endsWith(".tmp"))
    ) {
      continue;
    }
    try {
      const mtime = statSync(join(dir, name)).mtimeMs;
      if (latest === null || mtime > latest) latest = mtime;
    } catch {
      // raced entry — skip it
    }
  }
  return latest;
};

/**
 * The last moment the dir shows evidence of a COMPLETE owner: the newer of
 * the dir's own mtime (set at mkdir, bumped by every child add/remove — a
 * mid-setup holder stamps it on each step) and the newest owner record's
 * publish time. Null when nothing can be timed.
 */
const lastOwnerEvidenceMs = (dir: string): number | null => {
  let latest: number | null = null;
  try {
    latest = statSync(dir).mtimeMs;
  } catch {
    // unstatable — fall through to the record files
  }
  const record = ownerRecordTimeMs(dir);
  if (record !== null && (latest === null || record > latest)) {
    latest = record;
  }
  return latest;
};

/**
 * Bounded reclaim: true when no complete owner has touched this dir for
 * `UPDATE_LOCK_RECLAIM_MS`. An untimeable dir is never reclaimed on a guess —
 * failing to stat is a reason to keep holding, never to evict.
 */
const reclaimDue = (dir: string, nowMs: number): boolean => {
  const since = lastOwnerEvidenceMs(dir);
  return since !== null && nowMs - since > UPDATE_LOCK_RECLAIM_MS;
};

/**
 * Put a quarantined dir back at `lockDir` only when the name is still free.
 * The claim is one exclusive `mkdir` — never `existsSync` then `rename`:
 * POSIX `rename` REPLACES an empty target dir, so a fresh claim that landed
 * inside the check-then-move gap was silently overwritten and its owner's
 * publish then landed in a dir it did not create. Every regular file is
 * copied VERIFIED — created no-replace, fsync'd and re-read — and the
 * quarantined source is deleted only after EVERY copy lands whole: a
 * partial restore never destroys the only valid owner record.
 */
const moveBackNoReplace = (from: string, to: string): void => {
  moveBackGapHookForTests?.(from, to);
  try {
    mkdirSync(to);
  } catch {
    return; // the name was re-taken — leave the quarantine parked
  }
  const restored: string[] = [];
  let ok = true;
  let children: string[] = [];
  try {
    children = readdirSync(from).sort();
  } catch {
    ok = false; // nothing copyable — back out cleanly below
  }
  if (ok) {
    for (const child of children) {
      const src = join(from, child);
      const dst = join(to, child);
      try {
        if (!statSync(src).isFile()) continue;
      } catch {
        continue;
      }
      let created = false;
      let fd = -1;
      try {
        const data = readFileSync(src);
        fd = openSync(dst, "wx", 0o600);
        created = true;
        writeFileSync(fd, data);
        fsyncSync(fd);
        closeSync(fd);
        fd = -1;
        if (!readFileSync(dst).equals(data))
          throw new Error("restored copy failed verification");
        restored.push(child);
      } catch {
        ok = false;
        if (fd >= 0) {
          try {
            closeSync(fd);
          } catch {
            // best effort
          }
        }
        // Drop the partial file OUR copy created — never a foreign entry.
        if (created) {
          try {
            unlinkSync(dst);
          } catch {
            // best effort
          }
        }
        break;
      }
    }
  }
  if (!ok) {
    // Roll the fresh dir back to its claimed-empty state: only the files
    // THIS pass created are removed, then the dir itself when it is empty
    // again. The quarantined source is preserved whole for a later pass.
    for (const child of restored) {
      try {
        unlinkSync(join(to, child));
      } catch {
        // best effort
      }
    }
    try {
      rmdirSync(to);
    } catch {
      // a foreign entry arrived — leave the dir for its owner
    }
    return;
  }
  for (const child of restored) {
    try {
      unlinkSync(join(from, child));
    } catch {
      // best effort — a non-empty quarantine keeps the dir for the sweep
    }
  }
  try {
    rmdirSync(from);
  } catch {
    // best effort — foreign entries keep it parked for the sweep
  }
};

/**
 * Is the quarantined dir OURS? The dir inode captured at `mkdir` is DECISIVE
 * when known: it covers a failed publish that left nothing readable, AND it
 * keeps a foreign dir that swallowed our publish (the restored-during-setup
 * race) from being provable-ours by record alone. Only when the inode was
 * never captured (stat raced) do the record proofs apply: the published owner
 * nonce, or our lone un-renamed publish temp.
 */
const quarantinedIsOurs = (
  dir: string,
  ours: { readonly nonce: string; readonly ino: number | null },
): boolean => {
  if (ours.ino !== null) {
    try {
      return statSync(dir).ino === ours.ino;
    } catch {
      // stat raced — fall through to the record checks
    }
  }
  const owner = readOwnerFile(join(dir, OWNER_FILE));
  if (owner !== null) return owner.nonce === ours.nonce;
  const tmps = readTmpOwners(dir);
  return tmps.length === 1 && tmps[0]?.nonce === ours.nonce;
};

/**
 * Release only OUR lock. The dir is moved to quarantine FIRST — if it was
 * stolen and re-acquired while we held it, the dir we move is the NEW owner's,
 * the nonce check inside quarantine proves it isn't ours, and it moves back
 * untouched. A check-then-delete here was the old bug: between the read and
 * the recursive delete the path could change hands entirely.
 */
const releaseOrRestore = (
  lockDir: string,
  ours: { readonly nonce: string; readonly ino: number | null },
): void => {
  const quarantine = quarantinePath(lockDir, "rel", ours.nonce);
  try {
    renameSync(lockDir, quarantine);
  } catch {
    return; // already stolen/released — nothing of ours at that name
  }
  if (quarantinedIsOurs(quarantine, ours)) {
    try {
      rmSync(quarantine, { recursive: true, force: true });
    } catch {
      // best-effort — a leaked dir is recovered by the stale-steal path
    }
    return;
  }
  moveBackNoReplace(quarantine, lockDir);
};

const makeRelease = (
  lockDir: string,
  ours: { readonly nonce: string; readonly ino: number | null },
): TUpdateLockRelease => {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    ourNonces.delete(ours.nonce);
    releaseOrRestore(lockDir, ours);
  };
};

const dirIno = (dir: string): number | null => {
  try {
    return statSync(dir).ino;
  } catch {
    return null;
  }
};

/**
 * Nonces THIS process has minted and not yet released — the third leg of
 * same-process re-entry detection (pid AND start AND nonce). A lock record
 * carrying one of our nonces is our own earlier acquisition, so a second
 * acquire must fail fast instead of waiting out a self-deadlock; a record
 * with a FOREIGN nonce at our pid + start is the same-second PID-reuse twin
 * and is simply held — it must never look like ours.
 */
const ourNonces = new Set<string>();

/** This process's start identity under the DEFAULT reader, cached (it cannot
 *  change). Custom readers (tests) compute fresh each call. */
let ownStart: string | null = null;
const myStartIdentity = (
  read: TProcessStartIdentityReader = processStartIdentity,
): string => {
  if (read === processStartIdentity && ownStart !== null) return ownStart;
  let start: string;
  try {
    start = read(process.pid) ?? "";
  } catch {
    start = "";
  }
  if (read === processStartIdentity) ownStart = start;
  return start;
};

/**
 * Non-blocking acquire: mkdir + atomic owner.json publish, or null when held.
 * The owner record is written to a nonce-named temp then renamed — readers
 * only ever see a complete record. If the publish fails (or our dir was
 * replaced between mkdir and publish) the lock is released through the SAME
 * quarantine-verify path, so the cleanup can never delete a replacement
 * holder's dir (the round-2 bug).
 */
export const tryAcquireUpdateLock = (
  lockDir: string,
  opts?: { readonly startIdentity?: TProcessStartIdentityReader },
): TUpdateLockRelease | null => {
  const nonce = newNonce();
  const ours = { nonce, ino: null as number | null };
  // FSS-14: while a steal marker is up the lock name may be in the
  // rename gap — an mkdir that lands there must not produce a second
  // holder, so markers are honored before AND after our mkdir.
  if (stealInFlight(lockDir)) return null;
  try {
    mkdirSync(lockDir);
  } catch {
    return null;
  }
  ourNonces.add(nonce);
  ours.ino = dirIno(lockDir);
  if (stealInFlight(lockDir)) {
    // Our mkdir landed inside a steal's name gap. Undo ONLY our own dir —
    // it is still empty (nothing has been published into it) and still
    // provably ours by inode — then report held.
    try {
      if (ours.ino !== null && dirIno(lockDir) === ours.ino) rmdirSync(lockDir);
    } catch {
      // A restore raced the dir out from under us; leave it — it is no
      // longer ours to remove.
    }
    ourNonces.delete(nonce);
    return null;
  }
  const record: TOwnerRecord = {
    kind: OWNER_KIND,
    pid: process.pid,
    start: myStartIdentity(opts?.startIdentity),
    nonce,
  };
  const ownerPath = join(lockDir, OWNER_FILE);
  const tmp = join(lockDir, `${OWNER_FILE}.${nonce}.tmp`);
  let acquired = false;
  try {
    writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 });
    // Publish ONLY into a dir still provably ours and still unowned: the
    // inode covers a restore-rename swapping our dir out mid-setup; the
    // existsSync keeps the rename from clobbering a foreign owner.json that
    // landed in a restored dir (an empty-dir POSIX rename CAN replace).
    if (
      ours.ino !== null &&
      dirIno(lockDir) === ours.ino &&
      !existsSync(ownerPath)
    ) {
      renameSync(tmp, ownerPath);
      acquired = dirIno(lockDir) === ours.ino;
    }
  } catch {
    acquired = false;
  }
  if (!acquired) {
    // Our publish temp may have landed inside a foreign dir that was
    // restored over ours — remove exactly OUR nonce-named file so a lone
    // readable record can't mis-attribute a live foreign lock to this
    // process (it would look stealable once we exit).
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
  }
  // The dir is provably still ours when the inode matches — under this design
  // nobody else can move an unmarked dir, but a foreign release's quarantine
  // round-trip can briefly yoink it; the inode check is the decisive proof.
  if (acquired) {
    return makeRelease(lockDir, ours);
  }
  ourNonces.delete(nonce);
  releaseOrRestore(lockDir, ours);
  return null;
};

/**
 * Atomically steal a lock dir we ALREADY judged reclaimable: rename it aside
 * (only one racer wins the rename), re-validate INSIDE quarantine (the
 * holder may have released + a new owner re-acquired between our read and
 * the rename — the moved dir is then the new owner's — or a mid-setup
 * publish may have landed mid-race: its fresh record mtime is still inside
 * the bound), then delete only what is still stale or unproven past the
 * reclaim bound. A proven-live owner — or anything still inside the bound —
 * moves back no-replace.
 */
const stealStaleLock = (
  lockDir: string,
  probes: {
    readonly pidAlive: (pid: number) => boolean;
    readonly startIdentity: TProcessStartIdentityReader;
  },
  now: () => number,
): boolean => {
  // FSS-14: the marker goes up BEFORE the rename so the name gap between
  // quarantine and any move-back is provably a steal in flight — a
  // concurrent mkdir in that window sees the marker and cannot become a
  // second holder.
  const nonce = newNonce();
  const marker = stealMarkerName(lockDir, nonce);
  try {
    mkdirSync(marker);
  } catch {
    return false; // another steal (or a stranded marker) is in flight
  }
  try {
    const quarantine = quarantinePath(lockDir, "steal", nonce);
    try {
      renameSync(lockDir, quarantine);
    } catch {
      return false; // already stolen/released by someone else
    }
    stealGapHookForTests?.(lockDir);
    const owner = readOwner(quarantine);
    const verdict = owner === null ? "unproven" : classifyOwner(owner, probes);
    if (
      verdict === "proven-live" ||
      (verdict === "unproven" && !reclaimDue(quarantine, now()))
    ) {
      moveBackNoReplace(quarantine, lockDir);
      return false;
    }
    try {
      rmSync(quarantine, { recursive: true, force: true });
    } catch {
      // best-effort — a leftover `.steal-*` dir is adjudicated on the next pass
    }
    return true;
  } finally {
    try {
      rmdirSync(marker);
    } catch {
      // best-effort — a stranded marker is swept once its pid dies or it ages
    }
  }
};

/**
 * Adjudicate steal/release residue a crashed contender left beside
 * `lockDir` (FSS-14): a `.stealing-<pid>-<nonce>` marker whose creator pid
 * is dead (or whose age is past the reclaim bound) is removed — a live
 * marker is still honored. A stranded `.steal-*`/`.rel-*` quarantine dir is
 * re-validated exactly like a fresh steal: a proven-live owner moves back
 * when the name is free (and is deleted when a successor already holds the
 * name — the stranded record is inert), anything stale or unproven past the
 * bound is deleted, and a fresh unproven dir is left for the next pass.
 */
const sweepUpdateLockResidue = (
  lockDir: string,
  probes: {
    readonly pidAlive: (pid: number) => boolean;
    readonly startIdentity: TProcessStartIdentityReader;
  },
  now: () => number,
): void => {
  const parent = dirname(lockDir);
  const base = basename(lockDir);
  let names: string[];
  try {
    names = readdirSync(parent);
  } catch {
    return;
  }
  for (const name of names) {
    const markerPid = stealMarkerPid(lockDir, name);
    if (markerPid !== null) {
      const path = join(parent, name);
      try {
        const aged = now() - statSync(path).mtimeMs > UPDATE_LOCK_RECLAIM_MS;
        if (aged || !probes.pidAlive(markerPid)) rmdirSync(path);
      } catch {
        // raced or non-empty marker — retried on the next pass
      }
      continue;
    }
    if (!name.startsWith(`${base}.steal-`) && !name.startsWith(`${base}.rel-`))
      continue;
    const path = join(parent, name);
    try {
      if (!statSync(path).isDirectory()) continue;
    } catch {
      continue;
    }
    const owner = readOwner(path);
    const verdict = owner === null ? "unproven" : classifyOwner(owner, probes);
    if (verdict === "unproven" && !reclaimDue(path, now())) continue;
    if (verdict === "proven-live") {
      // A proven-live owner's quarantine is never deleted — that updater's
      // critical section may still be running. Restore it when the name is
      // free; when a successor holds the name, leave it for the next pass.
      if (!existsSync(lockDir)) moveBackNoReplace(path, lockDir);
      continue;
    }
    try {
      rmSync(path, { recursive: true, force: true });
    } catch {
      // retried on the next pass
    }
  }
};

/**
 * Acquire the swap lock, waiting up to `waitMs` for a live holder and stealing
 * locks whose owner is provably gone (dead pid or PID reused — a crashed
 * updater's lock is ALWAYS stealable, never held forever by a recycled pid),
 * and reclaiming dirs that have shown no complete, proven-live owner for
 * `UPDATE_LOCK_RECLAIM_MS` (a crash between mkdir and publish, or a holder
 * that can never prove its start, can no longer wedge writers forever).
 * Returns the release function, or null when the wait elapsed with a live
 * holder still in place (or a same-process re-entry was attempted — never
 * block on ourselves).
 *
 * Callers MUST wrap the critical section in try/finally + release: a leaked
 * holder only degrades later writers to the stale-steal path once its process
 * is gone, never to a deadlock.
 */
export const acquireUpdateLock = async (
  lockDir: string,
  opts: TUpdateLockOptions = {},
): Promise<TUpdateLockRelease | null> => {
  const waitMs = opts.waitMs ?? UPDATE_LOCK_WAIT_MS;
  const now = opts.now ?? Date.now;
  const sleep =
    opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const probes = {
    pidAlive: opts.pidAlive ?? defaultPidAlive,
    startIdentity: opts.startIdentity ?? processStartIdentity,
  };
  const deadline = now() + waitMs;
  for (;;) {
    sweepUpdateLockResidue(lockDir, probes, now);
    const release = tryAcquireUpdateLock(lockDir, {
      startIdentity: probes.startIdentity,
    });
    if (release !== null) return release;
    const owner = readOwner(lockDir);
    // Same-process re-entry requires pid AND start AND nonce — but a nonce
    // we minted can only live in a record this process published, so a hit
    // proves all three. Report busy immediately instead of waiting out a
    // self-deadlock. A foreign record at our pid+start with an UNOWNED
    // nonce (same-second PID reuse) is just a live lock: wait like any
    // other, never self-identify.
    if (owner !== null && ourNonces.has(owner.nonce)) {
      return null;
    }
    const verdict = owner === null ? "unproven" : classifyOwner(owner, probes);
    // Provably dead → steal now. Unproven (unmarked, unreadable, or a live
    // pid the record can't prove) → held ONLY until the dir has shown no
    // complete owner for the reclaim bound, then stolen through the same
    // quarantine path. Proven-live → never stolen, whatever the age.
    if (
      verdict === "stale" ||
      (verdict === "unproven" && reclaimDue(lockDir, now()))
    ) {
      if (stealStaleLock(lockDir, probes, now)) continue;
    }
    if (now() >= deadline) return null;
    await sleep(POLL_MS);
  }
};

/**
 * Scoped convenience: acquire → run `work` → release. Returns null when the
 * lock could not be acquired inside the wait window.
 */
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
