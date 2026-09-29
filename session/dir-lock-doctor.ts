/** Explicit, generation-bound legacy lock clearance. Never called from normal acquisition. */
import { existsSync, lstatSync, opendirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { performance } from "node:perf_hooks";
import type { TLockControl, TLockKind } from "./dir-lock-control";
import {
  checkedNames,
  childDirectory,
  childExists,
  closeLockControl,
  ensureDirectory,
  errorCode,
  LegacyLockError,
  lockGeneration,
  lockNonce,
  openLockControl,
  openPinnedPath,
  readRecord,
  removeLinkedRecordTemp,
  sameChildGeneration,
  withLockGate,
  writeRecord,
} from "./dir-lock-control";
import {
  decodeDirLockActor,
  decodeDirLockBytes,
  encodeDirLockActor,
  parseDirLockControlName,
  parseDirLockOwnerRecord,
  parseDirLockPlan,
  parseDirLockTransactionName,
  parseStrictDirLockJson,
} from "./dir-lock-format";
import type { TDirectoryHandle } from "./dir-lock-fs";
import {
  close,
  removeEmptyChild,
  statDescriptor,
  unlinkChild,
} from "./dir-lock-fs";
import type {
  TLegacyArtifact,
  TLegacyProcessObservation,
  TLegacySample,
} from "./dir-lock-legacy";
import {
  classifyLegacyProcessKind,
  inspectLegacyHold,
  loadLegacySamples,
  namespaceSuffix,
  newClaimAssociation,
  observeLegacyProcess,
  recordGeneration,
  sameLegacyArtifact,
  scanLegacyArtifacts,
} from "./dir-lock-legacy";
import { listDarwinPids } from "./dir-lock-process";
import {
  isBootScopedStartIdentity,
  legacyProcessStartIdentity,
  normalizeProcessStartIdentity,
  processIdentityStatus,
  processStartIdentity,
} from "./local-runtime";

export type TDoctorDomain = { readonly path: string; readonly kind: TLockKind };
export type TDoctorReport = {
  readonly code: 0 | 2 | 73 | 74;
  readonly status:
    | "cleared"
    | "invalid-arguments"
    | "LEGACY_CLEAR_REFUSED"
    | "LEGACY_CLEAR_INCOMPLETE";
  readonly removed: readonly string[];
  readonly retained: readonly string[];
  readonly refused: readonly string[];
  readonly pending: readonly string[];
  readonly excludedByKind: readonly {
    readonly pid: number;
    readonly comm: string;
  }[];
  readonly historicalPidSampleTruncated: boolean;
  readonly detectorLimits: readonly string[];
};
type TDoctorEntry = {
  readonly name: string;
  readonly generation: string;
  readonly bytes: string;
  readonly cleanupClass: string;
};
export type TDoctorPlan = {
  readonly version: 3;
  readonly schema: 1;
  readonly operation: "clear-legacy";
  readonly parentGeneration: string;
  readonly target: string;
  readonly targetType: "directory" | "regular";
  readonly targetGeneration: string;
  readonly basis:
    | "legacy-container"
    | "legacy-live-records"
    | "legacy-shadow"
    | "legacy-file"
    | "terminal-copy";
  readonly removeEmpty: boolean;
  readonly entries: readonly TDoctorEntry[];
  readonly targetBytes: string | null;
};
const LIMIT_TEXT =
  "Piped, renamed, or otherwise unattributed workers can be outside detector coverage.";
const PLAN_KEYS = [
  "version",
  "schema",
  "operation",
  "parentGeneration",
  "target",
  "targetType",
  "targetGeneration",
  "basis",
  "removeEmpty",
  "entries",
  "targetBytes",
] as const;
const ENTRY_KEYS = ["name", "generation", "bytes", "cleanupClass"] as const;
const BASIS = new Set([
  "legacy-container",
  "legacy-live-records",
  "legacy-shadow",
  "legacy-file",
  "terminal-copy",
]);
const INTENT = /^clear\.v3\.[0-9a-f]{32}$/;
const SAMPLE = /^sample\.v3\.[0-9a-f]{32}\.json$/;
const GENERATION = /^[0-9a-f]{16}\.[0-9a-f]{16}$/;
const NAME = /^[^/\0]+$/;
const PID = /^[1-9][0-9]{0,9}$/;
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean =>
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const validName = (value: unknown): value is string =>
  typeof value === "string" &&
  value !== "." &&
  value !== ".." &&
  NAME.test(value) &&
  Buffer.byteLength(value) <= 255;
const validGeneration = (value: unknown): value is string =>
  typeof value === "string" && GENERATION.test(value);
const canonicalPid = (value: string): boolean =>
  PID.test(value) && Number(value) <= 2147483647;

export const parseDoctorPlan = (
  bytes: Uint8Array | string,
): TDoctorPlan | null => {
  const value = parseStrictDirLockJson(bytes, 65536);
  if (
    !record(value) ||
    !exact(value, PLAN_KEYS) ||
    value.version !== 3 ||
    value.schema !== 1 ||
    value.operation !== "clear-legacy" ||
    !validGeneration(value.parentGeneration) ||
    !validName(value.target) ||
    !validGeneration(value.targetGeneration) ||
    (value.targetType !== "directory" && value.targetType !== "regular") ||
    typeof value.basis !== "string" ||
    !BASIS.has(value.basis) ||
    typeof value.removeEmpty !== "boolean" ||
    !Array.isArray(value.entries) ||
    value.entries.length > 32 ||
    (value.targetBytes !== null &&
      (typeof value.targetBytes !== "string" ||
        decodeDirLockBytes(value.targetBytes) === null))
  )
    return null;
  for (const entry of value.entries) {
    if (
      !record(entry) ||
      !exact(entry, ENTRY_KEYS) ||
      !validName(entry.name) ||
      !validGeneration(entry.generation) ||
      typeof entry.bytes !== "string" ||
      decodeDirLockBytes(entry.bytes) === null ||
      typeof entry.cleanupClass !== "string" ||
      !["owner", "guard", "temp", "terminal-copy"].includes(entry.cleanupClass)
    )
      return null;
  }
  if (
    value.targetType === "regular"
      ? value.entries.length !== 0 ||
        value.removeEmpty ||
        value.targetBytes === null
      : value.targetBytes !== null
  )
    return null;
  if (
    new Set(value.entries.map((entry: TDoctorEntry) => entry.name)).size !==
    value.entries.length
  )
    return null;
  return value as TDoctorPlan;
};
const emptyReport = (): TDoctorReport => ({
  code: 0,
  status: "cleared",
  removed: [],
  retained: [],
  refused: [],
  pending: [],
  excludedByKind: [],
  historicalPidSampleTruncated: false,
  detectorLimits: [LIMIT_TEXT],
});
const withCode = (
  report: TDoctorReport,
  code: 0 | 2 | 73 | 74,
): TDoctorReport => ({
  ...report,
  code,
  status:
    code === 0
      ? "cleared"
      : code === 2
        ? "invalid-arguments"
        : code === 73
          ? "LEGACY_CLEAR_REFUSED"
          : "LEGACY_CLEAR_INCOMPLETE",
});
const add = (list: readonly string[], value: string): readonly string[] =>
  list.includes(value) ? list : [...list, value];

/** Parse shell argv without flattening argument boundaries. */
export const isInstallerCommand = (argv: readonly string[]): boolean => {
  if (!argv.length) return false;
  const command = basename(argv[0] ?? "");
  if (["bash", "sh", "dash", "zsh"].includes(command)) {
    let at = 1;
    while (at < argv.length) {
      const arg = argv[at] ?? "";
      if (arg === "--") {
        at++;
        break;
      }
      if (arg === "-c" || (arg.startsWith("-") && arg.includes("c"))) {
        const body = argv[at + 1] ?? "";
        return (
          /(?:^|\n)pidfile="\$1"; timeout_bin="\$2"; job_timeout="\$3"/.test(
            body,
          ) ||
          /(?:^|\n)(?:kind=openllm-env-lock\/v1|lockd="\$pidfile\.d")/.test(
            body,
          )
        );
      }
      if (!arg.startsWith("-") || arg === "-") break;
      at++;
    }
    return basename(argv[at] ?? "") === "install.sh";
  }
  return (
    argv.slice(1).some((arg) => basename(arg) === "install.sh") &&
    ["bun", "bunx", "node"].includes(command)
  );
};
type TProcessView = {
  readonly byPid: Map<number, TLegacyProcessObservation>;
  readonly blockers: string[];
};
const listLinuxPids = (): number[] => {
  const dir = opendirSync("/proc");
  const pids: number[] = [];
  try {
    let entry = dir.readSync();
    while (entry !== null) {
      if (/^[1-9][0-9]*$/.test(entry.name)) {
        pids.push(Number(entry.name));
        if (pids.length > 32768)
          throw new Error("incomplete Linux process enumeration");
      }
      entry = dir.readSync();
    }
  } finally {
    dir.closeSync();
  }
  return pids;
};
export type TDoctorProcessDeps = {
  readonly observe: (pid: number) => TLegacyProcessObservation;
  readonly listPids: () => readonly number[] | null;
  readonly recordedStatus: (
    pid: number,
    start: string,
    budget: number,
  ) => "alive" | "dead" | "unknown";
};
const realProcessDeps: TDoctorProcessDeps = {
  observe: observeLegacyProcess,
  listPids: () =>
    process.platform === "linux"
      ? listLinuxPids()
      : process.platform === "darwin"
        ? listDarwinPids()
        : null,
  recordedStatus: (pid, start, budget) =>
    processIdentityStatus(
      pid,
      start,
      (id) => processStartIdentity(id, budget),
      (id) => legacyProcessStartIdentity(id, budget),
    ),
};
const processView = (
  deadline: number,
  deps: TDoctorProcessDeps,
): TProcessView => {
  const pids = deps.listPids();
  if (pids === null || pids.length > 32768)
    throw new Error("unsupported or incomplete process enumeration");
  const byPid = new Map<number, TLegacyProcessObservation>();
  const blockers: string[] = [];
  const installerPids: number[] = [];
  const ownUid = process.getuid?.();
  for (const pid of pids) {
    if (performance.now() > deadline)
      throw new Error("doctor process-scan budget exhausted");
    if (pid === process.pid) continue;
    let observed = deps.observe(pid);
    if (observed.state === "unknown") observed = deps.observe(pid);
    byPid.set(pid, observed);
    if (observed.state === "dead") continue;
    if (observed.uid !== null && observed.uid !== ownUid) continue;
    if (
      observed.uid === null ||
      observed.state === "unknown" ||
      observed.kind === "unknown" ||
      observed.argv === null
    ) {
      blockers.push(`incomplete process evidence for PID ${pid}`);
      continue;
    }
    if (observed.argv !== null && isInstallerCommand(observed.argv)) {
      installerPids.push(pid);
      blockers.push(
        `live installer PID ${pid} (${observed.comm ?? "unknown"})`,
      );
    }
  }
  const childrenByParent = new Map<number, number[]>();
  for (const [pid, observed] of byPid) {
    if (observed.parentPid === null) continue;
    const children = childrenByParent.get(observed.parentPid) ?? [];
    children.push(pid);
    childrenByParent.set(observed.parentPid, children);
  }
  const candidates = new Set(installerPids);
  const queue = [...installerPids];
  for (let head = 0; head < queue.length; head++) {
    if (performance.now() > deadline)
      throw new Error("doctor process-scan budget exhausted");
    for (const pid of childrenByParent.get(queue[head] ?? -1) ?? []) {
      if (candidates.has(pid)) continue;
      candidates.add(pid);
      queue.push(pid);
      const observed = byPid.get(pid);
      if (observed !== undefined && observed.state !== "dead")
        blockers.push(
          `live installer worker PID ${pid} (${observed.comm ?? "unknown"})`,
        );
    }
  }
  return { byPid, blockers };
};
const evaluateSamples = (
  ctx: TLockControl,
  artifacts: readonly TLegacyArtifact[],
  samples: readonly TLegacySample[],
  view: TProcessView,
  overflow: boolean,
  deadline: number,
  deps: TDoctorProcessDeps,
): {
  blockers: string[];
  excluded: { pid: number; comm: string }[];
  uncertain: string[];
} => {
  const blockers: string[] = [];
  const excluded: { pid: number; comm: string }[] = [];
  const uncertain: string[] = [];
  // A removed artifact does not end its recorded actor.
  const evidence: readonly TLegacyArtifact[] = [
    ...artifacts,
    ...samples.filter(
      (sample) =>
        !artifacts.some((artifact) =>
          sameLegacyArtifact(sample, artifact, ctx.path),
        ),
    ),
  ];
  for (const artifact of evidence) {
    if (
      artifact.artifactType === "unknown" ||
      artifact.artifactGeneration === null ||
      (artifact.artifactEvidence.bytes === null &&
        artifact.artifactType === "regular")
    ) {
      uncertain.push(join(dirname(ctx.path), artifact.relativePath));
      continue;
    }
    if (artifact.pid === null) continue;
    const sample = samples.find((item) =>
      sameLegacyArtifact(item, artifact, ctx.path),
    );
    if (sample === undefined) {
      if (!overflow) {
        uncertain.push(join(dirname(ctx.path), artifact.relativePath));
        continue;
      }
      const current =
        view.byPid.get(artifact.pid) ?? deps.observe(artifact.pid);
      if (
        current.state === "dead" ||
        (current.uid !== null && current.uid !== process.getuid?.())
      )
        continue;
      if (current.state === "live" && current.kind === "other")
        excluded.push({ pid: artifact.pid, comm: current.comm ?? "unknown" });
      else
        blockers.push(
          `close process PID ${artifact.pid} (${current.comm ?? "unknown"}) before retrying doctor; it may be an older lock actor.`,
        );
      continue;
    }
    if (sample.capturedIdentity === "dead") continue;
    const current = view.byPid.get(sample.pid) ?? deps.observe(sample.pid);
    if (
      current.state === "dead" ||
      (current.uid !== null && current.uid !== process.getuid?.())
    )
      continue;
    if (
      sample.captureBoot !== null &&
      current.boot !== null &&
      sample.captureBoot !== current.boot
    )
      continue;
    if (
      sample.capturedIdentity !== "unknown" &&
      current.identity !== null &&
      sample.capturedIdentity !== current.identity
    )
      continue;
    const recordedStart = legacyRecordedStart(ctx, artifact);
    if (recordedStart !== null) {
      const remaining = (): number =>
        Math.min(1500, Math.max(0, deadline - performance.now()));
      if (
        remaining() > 0 &&
        deps.recordedStatus(sample.pid, recordedStart, remaining()) === "dead"
      )
        continue;
    }
    if (current.state !== "live") {
      blockers.push(`unknown state for actor PID ${sample.pid}`);
      continue;
    }
    if (current.kind === "other")
      excluded.push({ pid: sample.pid, comm: current.comm ?? "unknown" });
    else
      blockers.push(
        `close process PID ${sample.pid} (${current.comm ?? "unknown"}) before retrying doctor; it may be an older lock actor.`,
      );
  }
  return { blockers, excluded, uncertain };
};

const flatRecord = (bytes: Buffer): boolean => {
  if (bytes.length > 1024 || bytes.includes(0)) return false;
  const text = bytes.toString("utf8");
  if (Buffer.from(text).length !== bytes.length || text.split("\n").length > 2)
    return false;
  const first = /^([1-9][0-9]{0,9})(?:[ \t].*)?\n?$/.exec(text);
  if (first !== null && canonicalPid(first[1] ?? "")) return true;
  const env =
    /^kind=openllm-env-lock\/v1 pid=([1-9][0-9]{0,9}) start=([^\n]+) nonce=([0-9a-fA-F]+)\n?$/.exec(
      text,
    );
  return env !== null && canonicalPid(env[1] ?? "");
};
const legacyJsonOwner = (kind: TLockKind, bytes: Buffer): boolean => {
  if (kind !== "u" && kind !== "r") return false;
  const value = parseStrictDirLockJson(bytes, 1024);
  if (!record(value) || !exact(value, ["kind", "pid", "start", "nonce"]))
    return false;
  const expected =
    kind === "u" ? "openllm-update-lock/v1" : "openllm-restore-lock/v1";
  return (
    value.kind === expected &&
    typeof value.pid === "number" &&
    Number.isInteger(value.pid) &&
    value.pid > 0 &&
    value.pid <= 2147483647 &&
    typeof value.start === "string" &&
    value.start.length <= 64 &&
    /^[\x20-\x7e]*$/.test(value.start) &&
    typeof value.nonce === "string" &&
    /^[0-9a-f]{32}$/.test(value.nonce)
  );
};
const legacyRecordedStart = (
  ctx: TLockControl,
  artifact: TLegacyArtifact,
): string | null => {
  if (
    artifact.artifactType !== "regular" ||
    artifact.artifactEvidence.bytes === null ||
    artifact.pid === null
  )
    return null;
  const decoded = decodeDirLockBytes(artifact.artifactEvidence.bytes);
  if (decoded === null) return null;
  const bytes = Buffer.from(decoded);
  const supportedStart = (start: string): string | null => {
    const normalized = normalizeProcessStartIdentity(start);
    return Buffer.byteLength(normalized) <= 64 &&
      (isBootScopedStartIdentity(normalized) ||
        /^(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [0-9]{4}$/.test(
          normalized,
        ))
      ? normalized
      : null;
  };
  if (ctx.kind === "e") {
    const match =
      /^kind=openllm-env-lock\/v1 pid=([1-9][0-9]{0,9}) start=([^\n]+) nonce=([0-9a-fA-F]+)\n?$/.exec(
        bytes.toString("utf8"),
      );
    return match !== null && Number(match[1]) === artifact.pid
      ? supportedStart(match[2] ?? "")
      : null;
  }
  if (!legacyJsonOwner(ctx.kind, bytes)) return null;
  const value = parseStrictDirLockJson(bytes, 1024);
  return record(value) &&
    value.pid === artifact.pid &&
    typeof value.start === "string"
    ? supportedStart(value.start)
    : null;
};
const supportedRegularTarget = (
  ctx: TLockControl,
  target: string,
  bytes: Buffer,
): boolean => {
  if (ctx.kind === "e") return flatRecord(bytes);
  if (ctx.kind === "u" || ctx.kind === "r")
    return (
      legacyJsonOwner(ctx.kind, bytes) ||
      (ctx.kind === "r" &&
        /^([1-9][0-9]{0,9}) [0-9]+\n?$/.test(bytes.toString("utf8")))
    );
  if (ctx.kind === "v" || ctx.kind === "a")
    return (
      flatRecord(bytes) ||
      (ctx.kind === "a" && target.endsWith(".launch") && bytes.length === 0)
    );
  return false;
};
const allowedChild = (
  ctx: TLockControl,
  name: string,
  bytes: Buffer,
  anchor: boolean,
): string | null => {
  if (name === "owner.v3" || /^owner\.v3\.[0-9a-f]{32}\.tmp$/.test(name)) {
    const claim = parseDirLockOwnerRecord(bytes);
    return claim !== null &&
      (name === "owner.v3" || name === `owner.v3.${claim.nonce}.tmp`) &&
      newClaimAssociation(ctx, bytes) === "terminal"
      ? "terminal-copy"
      : null;
  }
  if (name === "owner") {
    if (parseDirLockOwnerRecord(bytes) !== null)
      return newClaimAssociation(ctx, bytes) === "terminal"
        ? "terminal-copy"
        : null;
    return flatRecord(bytes) || (!anchor && bytes.length === 0)
      ? "owner"
      : null;
  }
  if (name === "owner.json") {
    if (parseDirLockOwnerRecord(bytes) !== null)
      return newClaimAssociation(ctx, bytes) === "terminal"
        ? "terminal-copy"
        : null;
    return legacyJsonOwner(ctx.kind, bytes) ? "owner" : null;
  }
  if (
    /^steal\.[1-9][0-9]{0,9}\.[0-9a-fA-F]+$/.test(name) &&
    bytes.length <= 1024
  )
    return "guard";
  if (/^owner\.tmp\.[1-9][0-9]{0,9}$/.test(name) && bytes.length <= 1024)
    return "temp";
  if (
    /^owner\.json\.(?:[0-9a-f]{32}|[1-9][0-9]{0,9})\.tmp$/.test(name) &&
    legacyJsonOwner(ctx.kind, bytes)
  )
    return "temp";
  return null;
};
const parentTarget = (ctx: TLockControl, name: string): boolean =>
  namespaceSuffix(ctx, name) !== null;
const emptyAnchor = (ctx: TLockControl, name: string): boolean => {
  if (name !== ctx.base) return false;
  try {
    const dir = childDirectory(ctx.parent, name);
    try {
      return checkedNames(dir, 512).length === 0;
    } finally {
      close(dir);
    }
  } catch (error) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR")
      return false;
    throw error;
  }
};
const makePlan = (ctx: TLockControl, target: string): TDoctorPlan | null => {
  if (!parentTarget(ctx, target)) return null;
  let dir: TDirectoryHandle;
  try {
    dir = childDirectory(ctx.parent, target);
  } catch (error) {
    if (errorCode(error) !== "ENOTDIR") return null;
    const bytes = readRecord(ctx.parent, target, 1024);
    const terminalCopy = newClaimAssociation(ctx, bytes) === "terminal";
    if (!supportedRegularTarget(ctx, target, bytes) && !terminalCopy)
      return null;
    return {
      version: 3,
      schema: 1,
      operation: "clear-legacy",
      parentGeneration: lockGeneration(ctx.parent),
      target,
      targetType: "regular",
      targetGeneration: recordGeneration(ctx.parent, target),
      basis: terminalCopy ? "terminal-copy" : "legacy-file",
      removeEmpty: false,
      entries: [],
      targetBytes: bytes.toString("base64url"),
    };
  }
  try {
    const names = checkedNames(dir, 512);
    const entries: TDoctorEntry[] = [];
    for (const name of names) {
      const bytes = readRecord(dir, name, 1024);
      const cleanupClass = allowedChild(ctx, name, bytes, target === ctx.base);
      if (cleanupClass === null) return null;
      if (entries.length < 32)
        entries.push({
          name,
          generation: recordGeneration(dir, name),
          bytes: bytes.toString("base64url"),
          cleanupClass,
        });
    }
    const basis =
      target === ctx.base
        ? "legacy-live-records"
        : /\.stealing-|\.releasing-/.test(target)
          ? "legacy-shadow"
          : "legacy-container";
    return {
      version: 3,
      schema: 1,
      operation: "clear-legacy",
      parentGeneration: lockGeneration(ctx.parent),
      target,
      targetType: "directory",
      targetGeneration: lockGeneration(dir),
      basis,
      removeEmpty: names.length <= 32,
      entries,
      targetBytes: null,
    };
  } finally {
    close(dir);
  }
};
const maybeRecord = (dir: TDirectoryHandle, name: string): Buffer | null => {
  try {
    return readRecord(dir, name, 65536);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
};

/** Completed claims may retain publication metadata while a legacy hold exists. */
const completedControls = (ctx: TLockControl): string[] | null => {
  const terminal = new Set<string>();
  const records: string[] = [];
  const transactions: string[] = [];
  for (const name of checkedNames(ctx.control, 512)) {
    if (name === "meta.v3.lock" || name === "legacy.v3.hold") continue;
    if (/^[cbx]\.v3\./.test(name)) {
      const fields = name.split(".");
      if (
        fields.length !== 4 ||
        !["e", "u", "r", "v", "a"].includes(fields[2] ?? "") ||
        decodeDirLockActor(fields[3] ?? "") === null
      )
        return null;
      const dir = childDirectory(ctx.control, name);
      try {
        if (checkedNames(dir, 0).length !== 0) return null;
      } finally {
        close(dir);
      }
      if (fields[0] !== "b") terminal.add(`${fields[2]}.${fields[3]}`);
      records.push(name);
      continue;
    }
    if (name.startsWith("t.v3.")) {
      const transaction = parseDirLockTransactionName(name);
      if (transaction === null) return null;
      const dir = childDirectory(ctx.control, name);
      try {
        if (checkedNames(dir, 1).join() !== "plan.v3.json") return null;
        const plan = parseDirLockPlan(readRecord(dir, "plan.v3.json", 8192));
        if (
          plan === null ||
          plan.operation !== transaction.operation ||
          plan.generation !== transaction.generation ||
          plan.target !== ctx.base ||
          (plan.claim !== null &&
            encodeDirLockActor(plan.claim) !==
              encodeDirLockActor(transaction.actor))
        )
          return null;
      } finally {
        close(dir);
      }
      transactions.push(name);
      continue;
    }
    return null;
  }
  for (const name of [...records, ...transactions]) {
    const fields = name.split(".");
    const kind = fields[2];
    const token = name.startsWith("t.") ? fields[4] : fields[3];
    if (!terminal.has(`${kind}.${token}`)) return null;
  }
  return [
    ...transactions,
    ...records.filter((name) => name.startsWith("b.")),
    ...records.filter((name) => /^[cx]\./.test(name)),
  ];
};
const removeCompletedControls = (
  ctx: TLockControl,
  names: readonly string[],
): void => {
  for (const name of names) {
    const dir = childDirectory(ctx.control, name);
    try {
      if (name.startsWith("t.")) {
        if (checkedNames(dir, 1).join() !== "plan.v3.json")
          throw new Error("transaction changed");
        readRecord(dir, "plan.v3.json", 8192);
        unlinkChild(dir, "plan.v3.json");
      } else if (checkedNames(dir, 0).length !== 0)
        throw new Error("control record changed");
    } finally {
      close(dir);
    }
    removeEmptyChild(ctx.control, name);
  }
};
const applyPlan = (
  ctx: TLockControl,
  _intentName: string,
  plan: TDoctorPlan,
  recheck: () => boolean,
  removed: string[],
): boolean => {
  if (
    plan.parentGeneration !== lockGeneration(ctx.parent) ||
    !parentTarget(ctx, plan.target)
  )
    return false;
  if (plan.targetType === "regular") {
    if (!childExists(ctx.parent, plan.target)) return true;
    if (
      !recheck() ||
      recordGeneration(ctx.parent, plan.target) !== plan.targetGeneration
    )
      return false;
    const bytes = maybeRecord(ctx.parent, plan.target);
    if (bytes === null || bytes.toString("base64url") !== plan.targetBytes)
      return false;
    unlinkChild(ctx.parent, plan.target);
    removed.push(join(dirname(ctx.path), plan.target));
    return true;
  }
  let dir: TDirectoryHandle;
  try {
    dir = childDirectory(ctx.parent, plan.target);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return true;
    throw error;
  }
  try {
    if (lockGeneration(dir) !== plan.targetGeneration) return false;
    for (const entry of plan.entries) {
      if (!recheck()) return false;
      const bytes = maybeRecord(dir, entry.name);
      if (bytes === null) continue;
      if (
        recordGeneration(dir, entry.name) !== entry.generation ||
        bytes.toString("base64url") !== entry.bytes
      )
        return false;
      unlinkChild(dir, entry.name);
      removed.push(join(dirname(ctx.path), plan.target, entry.name));
    }
    if (!plan.removeEmpty) return true;
    if (checkedNames(dir, 32).length !== 0 || !recheck()) return false;
  } finally {
    close(dir);
  }
  try {
    if (!sameChildGeneration(ctx.parent, plan.target, plan.targetGeneration))
      return false;
    removeEmptyChild(ctx.parent, plan.target);
    removed.push(join(dirname(ctx.path), plan.target));
    return true;
  } catch (error) {
    if (["ENOTEMPTY", "EEXIST"].includes(errorCode(error) ?? "")) return false;
    throw error;
  }
};
const removeIntent = (hold: TDirectoryHandle, name: string): void => {
  const intent = childDirectory(hold, name);
  try {
    const entries = checkedNames(intent, 2);
    if (
      entries.some(
        (entry) => entry !== "plan.v3.json" && entry !== "plan.v3.tmp",
      )
    )
      throw new Error("unknown doctor intent record");
    if (entries.includes("plan.v3.json")) {
      removeLinkedRecordTemp(intent, "plan.v3.tmp", "plan.v3.json", 65536);
      readRecord(intent, "plan.v3.json", 65536);
      unlinkChild(intent, "plan.v3.json");
    } else if (entries.includes("plan.v3.tmp")) {
      // An incomplete intent cannot authorize target changes.
      readRecord(intent, "plan.v3.tmp", 65536);
      unlinkChild(intent, "plan.v3.tmp");
    }
  } finally {
    close(intent);
  }
  removeEmptyChild(hold, name);
};

export const clearLegacyLocks = (
  domains: readonly TDoctorDomain[],
  deps: TDoctorProcessDeps = realProcessDeps,
  options: {
    readonly sampleOnly?: boolean;
    readonly actors?: readonly number[];
  } = {},
): TDoctorReport => {
  let report = emptyReport();
  const deadline = performance.now() + 30000;
  const unique = [
    ...new Map(domains.map((domain) => [domain.path, domain])).values(),
  ];
  const contexts: TLockControl[] = [];
  try {
    for (const domain of unique) {
      if (!isAbsolute(domain.path))
        return withCode(
          { ...report, retained: add(report.retained, domain.path) },
          2,
        );
      if (!existsSync(dirname(domain.path))) continue;
      const ctx = openLockControl(domain.path, domain.kind);
      contexts.push(ctx);
      const observed = withLockGate(ctx, () => {
        try {
          inspectLegacyHold(ctx, deps.observe);
        } catch (error) {
          if (!(error instanceof LegacyLockError)) throw error;
        }
      });
      if (observed === null)
        report = {
          ...report,
          refused: add(report.refused, `metadata gate busy: ${domain.path}`),
        };
    }
    if (report.refused.length) return withCode(report, 73);
    if (options.sampleOnly) return report;
    if (!contexts.some((ctx) => childExists(ctx.control, "legacy.v3.hold")))
      return report;
    const currentView = (): TProcessView => {
      const view = processView(deadline, deps);
      for (const pid of options.actors ?? []) {
        const observed = deps.observe(pid);
        if (observed.state === "dead") continue;
        if (observed.state === "live" && observed.kind === "other") continue;
        view.blockers.push(
          `close process PID ${pid} (${observed.comm ?? "unknown"}) before retrying doctor; it may be an older lock actor.`,
        );
      }
      return view;
    };
    let view = currentView();
    if (view.blockers.length) report = { ...report, refused: view.blockers };
    // Initial preflight across every domain. No target deletion until all pass.
    for (const ctx of contexts) {
      const artifacts = scanLegacyArtifacts(ctx);
      if (!childExists(ctx.control, "legacy.v3.hold") && !artifacts.length)
        continue;
      const hold = childDirectory(ctx.control, "legacy.v3.hold");
      try {
        const samples = loadLegacySamples(hold);
        const decision = evaluateSamples(
          ctx,
          artifacts,
          samples,
          view,
          childExists(hold, "overflow.v3"),
          deadline,
          deps,
        );
        report = {
          ...report,
          refused: [...report.refused, ...decision.blockers],
          retained: [...report.retained, ...decision.uncertain],
          excludedByKind: [...report.excludedByKind, ...decision.excluded],
          historicalPidSampleTruncated:
            report.historicalPidSampleTruncated ||
            childExists(hold, "overflow.v3"),
        };
        if (completedControls(ctx) === null)
          report = {
            ...report,
            retained: add(
              report.retained,
              `${ctx.path}: active or unresolved new control`,
            ),
          };
        for (const name of checkedNames(ctx.parent, 4096))
          if (
            parentTarget(ctx, name) &&
            !emptyAnchor(ctx, name) &&
            makePlan(ctx, name) === null
          )
            report = {
              ...report,
              retained: add(report.retained, `${ctx.path}: ${name}`),
            };
      } finally {
        close(hold);
      }
    }
    if (report.refused.length) return withCode(report, 73);
    if (report.retained.length) return withCode(report, 74);
    for (const ctx of contexts) {
      const entered = withLockGate(ctx, () => {
        if (!childExists(ctx.control, "legacy.v3.hold")) return true;
        const hold = childDirectory(ctx.control, "legacy.v3.hold");
        try {
          const recheck = (): boolean => {
            view = currentView();
            if (view.blockers.length) return false;
            const decision = evaluateSamples(
              ctx,
              scanLegacyArtifacts(ctx),
              loadLegacySamples(hold),
              view,
              childExists(hold, "overflow.v3"),
              deadline,
              deps,
            );
            if (decision.blockers.length || decision.uncertain.length)
              return false;
            return true;
          };
          for (const name of checkedNames(hold, 162).filter((entry) =>
            INTENT.test(entry),
          )) {
            const intent = childDirectory(hold, name);
            let plan: TDoctorPlan | null = null;
            let published = false;
            try {
              published = childExists(intent, "plan.v3.json");
              if (published) {
                removeLinkedRecordTemp(
                  intent,
                  "plan.v3.tmp",
                  "plan.v3.json",
                  65536,
                );
                plan = parseDoctorPlan(
                  readRecord(intent, "plan.v3.json", 65536),
                );
              }
            } finally {
              close(intent);
            }
            if (!published) {
              removeIntent(hold, name);
              continue;
            }
            if (
              plan === null ||
              !applyPlan(ctx, name, plan, recheck, report.removed as string[])
            )
              return false;
            removeIntent(hold, name);
          }
          for (const name of checkedNames(ctx.parent, 4096).filter((entry) =>
            parentTarget(ctx, entry),
          )) {
            if (emptyAnchor(ctx, name)) continue;
            let finished = false;
            for (let batch = 0; batch < 16; batch++) {
              if (!recheck()) return false;
              const plan = makePlan(ctx, name);
              if (plan === null) return false;
              const intentName = `clear.v3.${lockNonce()}`;
              const intent = ensureDirectory(hold, intentName);
              try {
                writeRecord(
                  intent,
                  "plan.v3.tmp",
                  "plan.v3.json",
                  JSON.stringify(plan),
                );
              } finally {
                close(intent);
              }
              if (
                !applyPlan(
                  ctx,
                  intentName,
                  plan,
                  recheck,
                  report.removed as string[],
                )
              )
                return false;
              removeIntent(hold, intentName);
              if (plan.targetType === "regular" || plan.removeEmpty) {
                finished = true;
                break;
              }
            }
            if (!finished) return false;
          }
          if (!recheck() || scanLegacyArtifacts(ctx).length) return false;
          const completed = completedControls(ctx);
          if (completed === null) return false;
          removeCompletedControls(ctx, completed);
          for (const name of checkedNames(hold, 162)) {
            if (!/^sample\.v3\.[0-9a-f]{32}\.tmp$/.test(name)) continue;
            const published = `${name.slice(0, -4)}.json`;
            if (childExists(hold, published)) {
              removeLinkedRecordTemp(hold, name, published, 8192);
            } else {
              // A partial sample gives no cleanup authority.
              // The gate excludes sample writers during this removal.
              readRecord(hold, name, 8192);
              unlinkChild(hold, name);
            }
          }
          for (const name of checkedNames(hold, 162)) {
            if (SAMPLE.test(name)) {
              readRecord(hold, name, 8192);
              unlinkChild(hold, name);
            } else if (name === "overflow.v3") {
              const overflow = childDirectory(hold, name);
              try {
                checkedNames(overflow, 0);
              } finally {
                close(overflow);
              }
              removeEmptyChild(hold, name);
            } else return false;
          }
        } finally {
          close(hold);
        }
        removeEmptyChild(ctx.control, "legacy.v3.hold");
        return true;
      });
      if (entered !== true) {
        report = { ...report, pending: add(report.pending, ctx.path) };
        return withCode(report, 73);
      }
    }
    return report;
  } catch (error) {
    return withCode(
      {
        ...report,
        pending: add(
          report.pending,
          error instanceof Error ? error.message : String(error),
        ),
      },
      74,
    );
  } finally {
    for (const ctx of contexts) closeLockControl(ctx);
  }
};

/** Inspect only supplied parents for controls whose names encode a supported lock. */
export const discoverKnownLockDomains = (
  knownParentDirs: readonly string[],
): TDoctorDomain[] => {
  const domains: TDoctorDomain[] = [];
  for (const parentPath of new Set(knownParentDirs)) {
    if (!isAbsolute(parentPath))
      throw new Error("doctor parent must be absolute");
    if (!existsSync(parentPath)) continue;
    const parent = openPinnedPath(parentPath);
    try {
      const stat = statDescriptor(parent.fd);
      if (
        stat.uid !== BigInt(process.getuid?.() ?? -1) ||
        (stat.mode & 0o022n) !== 0n
      )
        throw new Error(`doctor parent is not private: ${parentPath}`);
      for (const name of checkedNames(parent, 4096)) {
        const lockName = parseDirLockControlName(name);
        if (lockName === null) continue;
        const kind: TLockKind | null = lockName.endsWith(".update.lock")
          ? "u"
          : lockName === ".openllm-restore.lock"
            ? "r"
            : lockName.endsWith(".pid.d")
              ? "v"
              : lockName.endsWith(".launch.v3")
                ? "a"
                : lockName.endsWith(".lock.d")
                  ? "e"
                  : null;
        if (kind !== null)
          domains.push({ path: join(parentPath, lockName), kind });
      }
    } finally {
      close(parent);
    }
  }
  return domains;
};

export const stateLockParents = (root: string): readonly string[] => [
  root,
  join(root, "bin"),
  join(root, "cli-install"),
];

export const clientRestoreLockDomains = (
  home: string = process.env.HOME || homedir(),
): readonly TDoctorDomain[] =>
  [".grok", ".hermes"].map((name) => ({
    path: join(home, name, ".openllm-restore.lock"),
    kind: "r",
  }));

export type TDoctorClearArgs = {
  readonly entry?: string;
  readonly domains: readonly (
    | TDoctorDomain
    | { readonly kind: "env"; readonly envFile: string }
    | { readonly kind: "launch"; readonly jobDir: string; readonly cmd: string }
  )[];
  readonly actors?: readonly number[];
  readonly mode?: "clear" | "sample";
  readonly onReport?: (report: TDoctorReport) => void;
};
export type TDoctorClearDeps = {
  readonly pidAlive: (pid: number) => boolean;
  readonly startIdentity: (pid: number) => string | null | undefined;
  readonly startEpochMs?: (pid: number) => number | null | undefined;
  readonly procInfo: (pid: number) => {
    readonly comm: string | null;
    readonly argv0: string | null;
    readonly unreadable: boolean;
  };
  readonly emit: (record: Record<string, unknown>) => void;
  readonly root: string;
  readonly processes?: TDoctorProcessDeps;
};

/** Both command entrypoints use this clearance path. */
export const doctorClearLegacyLocks = (
  args: TDoctorClearArgs,
  deps?: TDoctorClearDeps,
): number => {
  const injected: TDoctorProcessDeps | undefined = deps && {
    listPids: () => [],
    observe: (pid): TLegacyProcessObservation => {
      const alive = deps.pidAlive(pid);
      const identity = alive ? deps.startIdentity(pid) : null;
      const info = alive ? deps.procInfo(pid) : null;
      const argv = info?.argv0 === null || !info ? null : [info.argv0];
      return {
        state: alive ? "live" : "dead",
        uid: process.getuid?.() ?? null,
        identity: identity ?? null,
        boot: identity?.startsWith("boot:")
          ? (identity.split(":")[1] ?? null)
          : null,
        kind: info?.unreadable
          ? "unknown"
          : classifyLegacyProcessKind(info?.comm ?? null, argv),
        comm: info?.comm ?? null,
        argv,
        parentPid: null,
      };
    },
    recordedStatus: (pid, start) => {
      if (!deps.pidAlive(pid)) return "dead";
      const current = deps.startIdentity(pid);
      return current === undefined || current === null
        ? "unknown"
        : current === start
          ? "alive"
          : "dead";
    },
  };
  const processes = deps?.processes ?? injected ?? realProcessDeps;
  const report = clearLegacyLocks(
    args.domains.map((domain): TDoctorDomain => {
      if (domain.kind === "env")
        return { path: `${domain.envFile}.lock.d`, kind: "e" };
      if (domain.kind === "launch")
        return {
          path: join(domain.jobDir, `${domain.cmd}.launch.v3`),
          kind: "a",
        };
      return domain;
    }),
    processes,
    { actors: args.actors, sampleOnly: args.mode === "sample" },
  );
  for (const reason of report.refused) {
    const pid = Number(/PID ([0-9]+)/.exec(reason)?.[1]);
    const observed = Number.isFinite(pid) ? processes.observe(pid) : null;
    const runtime = [
      observed?.comm,
      observed?.argv?.[0] && basename(observed.argv[0]),
    ].some((name) => ["bun", "bunx", "node"].includes(name ?? ""));
    deps?.emit({
      t: "doctor",
      ev: "blocked-actor",
      pid,
      comm: observed?.comm,
      kind:
        observed?.kind === "unknown"
          ? "unreadable"
          : runtime
            ? "js-runtime"
            : observed?.kind,
      detail: reason,
    });
  }
  for (const actor of report.excludedByKind)
    deps?.emit({ t: "doctor", ev: "excluded-by-kind", ...actor });
  for (const path of report.removed)
    deps?.emit({ t: "doctor", ev: "removed", path });
  for (const path of report.retained)
    deps?.emit({ t: "doctor", ev: "retained", path });
  deps?.emit({ t: "doctor", ev: "verdict", verdict: report.status });
  args.onReport?.(report);
  return report.code;
};

export const runLegacyLockDoctor = async (
  args: readonly string[],
  defaultEnvFiles: readonly string[],
  additionalDomains: readonly TDoctorDomain[] = [],
  knownParentDirs: readonly string[] = [],
): Promise<number> => {
  const json = args.includes("--json");
  if (process.platform === "win32") {
    const report = {
      ...emptyReport(),
      detectorLimits: ["legacy lock clearance is not applicable on Windows"],
    };
    console.log(
      json
        ? JSON.stringify(report)
        : "not applicable on Windows: legacy lock clearance uses POSIX locks",
    );
    return report.code;
  }
  const domains: TDoctorDomain[] = [
    ...defaultEnvFiles.map((path) => ({
      path: `${path}.lock.d`,
      kind: "e" as const,
    })),
    ...additionalDomains,
  ];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--clear-legacy-locks") continue;
    if (arg === "--json") continue;
    if (
      arg === "--env-file" &&
      args[index + 1] !== undefined &&
      isAbsolute(args[index + 1] ?? "")
    ) {
      try {
        const envPath = args[index + 1] ?? "";
        const parent = openPinnedPath(dirname(envPath));
        close(parent);
        try {
          if (!lstatSync(envPath).isFile())
            throw new Error("--env-file is not a regular file");
        } catch (error) {
          if (errorCode(error) !== "ENOENT") throw error;
        }
      } catch (error) {
        const incomplete = withCode(
          {
            ...emptyReport(),
            retained: [
              `unreadable --env-file parent: ${args[index + 1]} (${error instanceof Error ? error.message : String(error)})`,
            ],
          },
          74,
        );
        console.log(
          json
            ? JSON.stringify(incomplete)
            : `${incomplete.status}: ${incomplete.retained.join("; ")}`,
        );
        return 74;
      }
      domains.push({ path: `${args[++index]}.lock.d`, kind: "e" });
      continue;
    }
    if (
      arg === "--restore-dir" &&
      args[index + 1] !== undefined &&
      isAbsolute(args[index + 1] ?? "")
    ) {
      const restoreDir = args[index + 1] ?? "";
      try {
        if (existsSync(restoreDir)) {
          const parent = openPinnedPath(restoreDir);
          close(parent);
        }
      } catch (error) {
        const incomplete = withCode(
          {
            ...emptyReport(),
            retained: [
              `unreadable --restore-dir: ${restoreDir} (${error instanceof Error ? error.message : String(error)})`,
            ],
          },
          74,
        );
        console.log(
          json
            ? JSON.stringify(incomplete)
            : `${incomplete.status}: ${incomplete.retained.join("; ")}`,
        );
        return 74;
      }
      domains.push({
        path: join(restoreDir, ".openllm-restore.lock"),
        kind: "r",
      });
      index += 1;
      continue;
    }
    const invalid = withCode(
      { ...emptyReport(), retained: [`invalid option: ${arg ?? ""}`] },
      2,
    );
    console.log(
      json
        ? JSON.stringify(invalid)
        : `${invalid.status}: ${invalid.retained.join(", ")}`,
    );
    return 2;
  }
  let report: TDoctorReport = emptyReport();
  try {
    doctorClearLegacyLocks({
      domains: [...domains, ...discoverKnownLockDomains(knownParentDirs)],
      onReport: (result): void => {
        report = result;
      },
    });
  } catch (error) {
    report = withCode(
      {
        ...emptyReport(),
        retained: [
          `domain discovery failed: ${error instanceof Error ? error.message : String(error)}`,
        ],
      },
      74,
    );
  }
  const details = [
    ...report.refused.map((reason) => `refused: ${reason}`),
    ...report.excludedByKind.map(
      (actor) => `excluded by kind: PID ${actor.pid} (${actor.comm})`,
    ),
    ...report.retained.map((reason) => `retained: ${reason}`),
    ...report.pending.map((reason) => `pending: ${reason}`),
  ];
  console.log(
    json
      ? JSON.stringify(report)
      : `${report.status}: removed ${report.removed.length}; retained ${report.retained.length}; refused ${report.refused.length}; pending ${report.pending.length}. ${details.join("; ")}${details.length ? ". " : ""}${LIMIT_TEXT}`,
  );
  return report.code;
};
