import { closeSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { basename, isAbsolute } from "node:path";
import type { TLockControl } from "./dir-lock-control";
import {
  checkedNames,
  childDirectory,
  childExists,
  ensureDirectory,
  errorCode,
  LegacyLockError,
  lockGeneration,
  lockNonce,
  readRecord,
  writeRecord,
} from "./dir-lock-control";
import {
  decodeDirLockBytes,
  encodeDirLockActor,
  formatDirLockControlName,
  formatDirLockGeneration,
  parseDirLockOwnerRecord,
  parseDirLockPlan,
  parseDirLockTransactionName,
  parseStrictDirLockJson,
} from "./dir-lock-format";
import type { TDirectoryHandle } from "./dir-lock-fs";
import {
  close,
  openChild,
  posixOpenFlags,
  removeEmptyChild,
  statDescriptor,
  unlinkChild,
} from "./dir-lock-fs";
import { observeDarwinProcess } from "./dir-lock-process";

export type TLegacyArtifact = {
  readonly relativePath: string;
  readonly parentGeneration: string;
  readonly artifactGeneration: string | null;
  readonly artifactType: "regular" | "directory" | "unknown";
  readonly artifactEvidence: {
    readonly name: string;
    readonly bytes: string | null;
  };
  readonly pid: number | null;
  readonly role:
    | "quarantine creator"
    | "release actor"
    | "guard actor"
    | "shadow actor"
    | "owner"
    | "launcher"
    | "identified worker";
};
export type TLegacyProcessKind =
  | "shell"
  | "install-script"
  | "openllm"
  | "openllmd"
  | "other"
  | "unknown";
export type TLegacyProcessObservation = {
  readonly state: "live" | "dead" | "unknown";
  readonly uid: number | null;
  readonly identity: string | null;
  readonly boot: string | null;
  readonly kind: TLegacyProcessKind;
  readonly comm: string | null;
  readonly argv: readonly string[] | null;
  readonly parentPid: number | null;
};
export type TLegacySample = {
  readonly version: 3;
  readonly domain: string;
  readonly parentGeneration: string;
  readonly relativePath: string;
  readonly artifactGeneration: string;
  readonly artifactType: "regular" | "directory";
  readonly artifactEvidence: {
    readonly name: string;
    readonly bytes: string | null;
  };
  readonly role: TLegacyArtifact["role"];
  readonly pid: number;
  readonly capturedIdentity: string;
  readonly captureBoot: string | null;
  readonly capturedKind: TLegacyProcessKind;
  readonly capturedComm: string | null;
};
const SAMPLE_NAME = /^sample\.v3\.[0-9a-f]{32}\.json$/;
const PID_TEXT = /^[1-9][0-9]{0,9}$/;
const SAMPLE_KEYS = [
  "version",
  "domain",
  "parentGeneration",
  "relativePath",
  "artifactGeneration",
  "artifactType",
  "artifactEvidence",
  "role",
  "pid",
  "capturedIdentity",
  "captureBoot",
  "capturedKind",
  "capturedComm",
] as const;
const KINDS = new Set<TLegacyProcessKind>([
  "shell",
  "install-script",
  "openllm",
  "openllmd",
  "other",
  "unknown",
]);
const ROLES = new Set<TLegacyArtifact["role"]>([
  "quarantine creator",
  "release actor",
  "guard actor",
  "shadow actor",
  "owner",
  "launcher",
  "identified worker",
]);
const SHELLS = new Set(["bash", "sh", "dash", "zsh"]);
const RUNTIMES = new Set(["bun", "bunx", "node"]);
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean =>
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const validPid = (value: number): boolean =>
  Number.isInteger(value) && value > 0 && value <= 2147483647;
const namedPid = (text: string): number | null => {
  const pid = Number(text);
  return PID_TEXT.test(text) && validPid(pid) ? pid : null;
};
const isGeneration = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{16}\.[0-9a-f]{16}$/.test(value);

export const hasProtocolTag = (name: string): boolean =>
  name.split(".").includes("v3");
export const namespaceSuffix = (
  ctx: Pick<TLockControl, "base" | "kind">,
  name: string,
): string | null => {
  if (ctx.kind === "a") {
    const command = ctx.base.replace(/\.launch(?:\.v3)?$/, "");
    if (name === `${command}.launch`) return "launch";
    if (name === `${command}.launch.v3`) return "launch.v3";
    if (name.startsWith(`${command}.launch.`))
      return name.slice(command.length + 1);
  }
  if (name === ctx.base) return "";
  if (name.startsWith(`${ctx.base}.`)) {
    const suffix = name.slice(ctx.base.length + 1);
    if (
      /^(?:steal-|rel-|stealing[.-]|releasing[.-])/.test(suffix) ||
      (ctx.kind === "r" && suffix.startsWith("stale-"))
    )
      return suffix;
  }
  if (ctx.kind === "e" || ctx.kind === "v") {
    const stem = ctx.base.endsWith(".d") ? ctx.base.slice(0, -2) : ctx.base;
    if (name === stem) return "";
    if (name.startsWith(`${stem}.`)) {
      const suffix = name.slice(stem.length + 1);
      if (ctx.kind === "e" && /^(?:stale\.|rel\.)/.test(suffix)) return suffix;
      if (ctx.kind === "v" && /^(?:parked-|tmp\.)/.test(suffix)) return suffix;
    }
  }
  return null;
};
/**
 * Remove an empty control directory. Call this only under the metadata gate.
 * The control is empty when it holds only the gate, the parent holds no
 * namespace entry (no live directory, shadow, residue, or legacy artifact),
 * and no claim, reservation, transaction, or hold remains. A caller that
 * still holds a gate descriptor sees `GateVanishedError` on its next gate
 * operation and opens the control again. A concurrent opener that created a
 * fresh gate keeps the directory: the final removal fails with ENOTEMPTY.
 * Returns true when this call removed the control directory.
 */
export const collectEmptyControl = (ctx: TLockControl): boolean => {
  for (const name of checkedNames(ctx.parent, 4096))
    if (namespaceSuffix(ctx, name) !== null) return false;
  const names = checkedNames(ctx.control, 512);
  if (names.length !== 1 || names[0] !== "meta.v3.lock") return false;
  unlinkChild(ctx.control, "meta.v3.lock");
  try {
    removeEmptyChild(ctx.parent, formatDirLockControlName(ctx.base));
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOTEMPTY" || code === "EEXIST" || code === "ENOENT")
      return false;
    throw error;
  }
  return true;
};
const roleFor = (name: string): TLegacyArtifact["role"] => {
  if (name.startsWith("steal.")) return "guard actor";
  if (/\.stale[.-]|\.steal-/.test(name)) return "quarantine creator";
  if (/\.rel\.|\.rel-/.test(name)) return "release actor";
  if (/\.stealing-|\.releasing-/.test(name)) return "shadow actor";
  if (/\.launch(?:\.|$)/.test(name)) return "launcher";
  return "owner";
};
const pidFor = (name: string, bytes: Buffer | null): number | null => {
  const named =
    /(?:^steal\.|\.(?:stale[.-]|rel\.|steal-|rel-|stealing-|releasing-|parked-|tmp\.))([1-9][0-9]{0,9})(?:[.-]|$)/.exec(
      name,
    )?.[1];
  if (named !== undefined) return namedPid(named);
  if (bytes === null) return null;
  const content = bytes.toString("utf8");
  const text =
    /(?:^|\s)pid=([1-9][0-9]{0,9})(?:\s|$)/.exec(content)?.[1] ??
    /^([1-9][0-9]{0,9})(?:\s|$)/.exec(content)?.[1];
  if (text !== undefined) return namedPid(text);
  const value = parseStrictDirLockJson(bytes, 1024);
  return record(value) && typeof value.pid === "number" && validPid(value.pid)
    ? value.pid
    : null;
};
export const recordGeneration = (
  parent: TDirectoryHandle,
  name: string,
): string => {
  const file = openChild(parent, name, posixOpenFlags().O_RDONLY);
  try {
    const stat = statDescriptor(file.fd);
    return formatDirLockGeneration(stat.dev, stat.ino);
  } finally {
    close(file);
  }
};

/** Exact new control evidence excludes the copied owner PID only. */
export const newClaimAssociation = (
  ctx: TLockControl,
  bytes: Buffer,
): "terminal" | "publication" | null => {
  const owner = parseDirLockOwnerRecord(bytes);
  if (owner === null || owner.kind !== ctx.kind) return null;
  const token = encodeDirLockActor(owner);
  for (const prefix of ["c", "x"]) {
    const name = `${prefix}.v3.${owner.kind}.${token}`;
    if (!childExists(ctx.control, name)) continue;
    const dir = childDirectory(ctx.control, name);
    try {
      if (checkedNames(dir, 0).length === 0) return "terminal";
    } finally {
      close(dir);
    }
  }
  for (const name of checkedNames(ctx.control, 512)) {
    const transaction = parseDirLockTransactionName(name);
    if (
      transaction?.operation !== "p" ||
      transaction.kind !== owner.kind ||
      encodeDirLockActor(transaction.actor) !== token
    )
      continue;
    const dir = childDirectory(ctx.control, name);
    try {
      const plan = parseDirLockPlan(readRecord(dir, "plan.v3.json", 8192));
      if (
        plan?.operation === "p" &&
        plan.target === ctx.base &&
        (plan.claim === null || encodeDirLockActor(plan.claim) === token) &&
        plan.generation === transaction.generation
      )
        return "publication";
    } catch {
      /* Incomplete transaction is not association authority. */
    } finally {
      close(dir);
    }
  }
  return null;
};

/** One-level namespace scan. Nested or unreadable entries are retained as unknown. */
export const scanLegacyArtifacts = (ctx: TLockControl): TLegacyArtifact[] => {
  const artifacts: TLegacyArtifact[] = [];
  const add = (
    parent: TDirectoryHandle,
    name: string,
    relativePath: string,
    tagged: boolean,
    anchor: boolean,
    depth: number,
  ): void => {
    let dir: TDirectoryHandle;
    try {
      dir = childDirectory(parent, name);
    } catch (error) {
      if (errorCode(error) === "ENOENT") throw error;
      if (errorCode(error) !== "ENOTDIR") {
        if (!tagged)
          artifacts.push({
            relativePath,
            parentGeneration: lockGeneration(parent),
            artifactGeneration: null,
            artifactType: "unknown",
            artifactEvidence: { name, bytes: null },
            role: roleFor(name),
            pid: pidFor(name, null),
          });
        return;
      }
      if (tagged) return;
      let bytes: Buffer | null = null;
      let generation: string | null = null;
      try {
        generation = recordGeneration(parent, name);
        bytes = readRecord(parent, name, 1024);
      } catch {
        /* Keep unknown evidence. */
      }
      artifacts.push({
        relativePath,
        parentGeneration: lockGeneration(parent),
        artifactGeneration: generation,
        artifactType: generation === null ? "unknown" : "regular",
        artifactEvidence: { name, bytes: bytes?.toString("base64url") ?? null },
        role: roleFor(name),
        pid:
          roleFor(name) === "owner" &&
          bytes !== null &&
          newClaimAssociation(ctx, bytes) !== null
            ? null
            : pidFor(name, bytes),
      });
      return;
    }
    try {
      if (!tagged && !anchor)
        artifacts.push({
          relativePath,
          parentGeneration: lockGeneration(parent),
          artifactGeneration: lockGeneration(dir),
          artifactType: "directory",
          artifactEvidence: { name, bytes: null },
          role: roleFor(name),
          pid: pidFor(name, null),
        });
      if (depth >= 1) return;
      for (const child of checkedNames(dir, 512)) {
        if (hasProtocolTag(child)) continue;
        add(dir, child, `${relativePath}/${child}`, false, false, depth + 1);
      }
    } finally {
      close(dir);
    }
  };
  for (const name of checkedNames(ctx.parent, 4096)) {
    const suffix = namespaceSuffix(ctx, name);
    if (suffix === null) continue;
    add(
      ctx.parent,
      name,
      name,
      suffix !== "" && hasProtocolTag(suffix),
      name === ctx.base,
      0,
    );
  }
  return artifacts;
};

export const classifyLegacyProcessKind = (
  comm: string | null,
  argv: readonly string[] | null,
): TLegacyProcessKind => {
  const names = [comm, argv?.[0] === undefined ? null : basename(argv[0])];
  if (names.some((name) => name !== null && SHELLS.has(name))) return "shell";
  if (names.includes("openllmd")) return "openllmd";
  if (
    names.includes("openllm") ||
    names.some((name) => name !== null && RUNTIMES.has(name))
  )
    return "openllm";
  if (argv?.some((value) => basename(value) === "install.sh"))
    return "install-script";
  return comm !== null && argv !== null ? "other" : "unknown";
};
const procArgv = (path: string): readonly string[] | null => {
  const fd = openSync(path, "r");
  try {
    const bytes = Buffer.allocUnsafe(1048577);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length === 0 || length > 1048576 || bytes[length - 1] !== 0)
      return null;
    return new TextDecoder("utf-8", { fatal: true })
      .decode(bytes.subarray(0, length - 1))
      .split("\0");
  } finally {
    closeSync(fd);
  }
};
/** Capture identity, terminal state, and kind from one Linux process generation. */
export const observeLegacyProcess = (
  pid: number,
): TLegacyProcessObservation => {
  const unknown: TLegacyProcessObservation = {
    state: "unknown",
    uid: null,
    identity: null,
    boot: null,
    kind: "unknown",
    comm: null,
    argv: null,
    parentPid: null,
  };
  if (!validPid(pid)) return unknown;
  if (process.platform === "darwin") {
    try {
      const observed = observeDarwinProcess(pid);
      return {
        ...observed,
        boot: null,
        kind: classifyLegacyProcessKind(observed.comm, observed.argv),
      };
    } catch {
      return unknown;
    }
  }
  if (process.platform !== "linux") return unknown;
  const path = `/proc/${pid}`;
  let uid: number;
  try {
    uid = statSync(path).uid;
  } catch (error) {
    return errorCode(error) === "ENOENT"
      ? { ...unknown, state: "dead" }
      : unknown;
  }
  let stat: string;
  try {
    stat = readFileSync(`${path}/stat`, "utf8");
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      try {
        statSync(path);
      } catch (second) {
        if (errorCode(second) === "ENOENT")
          return { ...unknown, state: "dead", uid };
      }
    }
    return { ...unknown, uid };
  }
  const end = stat.lastIndexOf(") ");
  const fields =
    end < 0
      ? []
      : stat
          .slice(end + 2)
          .trim()
          .split(" ");
  const state = fields[0];
  const ppid = fields[1] === undefined ? null : namedPid(fields[1]);
  if (state === "Z" || state === "X")
    return { ...unknown, state: "dead", uid, parentPid: ppid };
  if (!state || !fields[19] || !/^(?:0|[1-9][0-9]*)$/.test(fields[19]))
    return { ...unknown, uid, parentPid: ppid };
  let boot: string | null = null;
  try {
    const value = readFileSync(
      "/proc/sys/kernel/random/boot_id",
      "utf8",
    ).trim();
    if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value))
      boot = value;
  } catch {
    /* Identity stays unknown. */
  }
  const identity = boot === null ? null : `boot:${boot}:${fields[19]}`;
  let comm: string | null = null;
  let argv: readonly string[] | null = null;
  try {
    comm = readFileSync(`${path}/comm`, "utf8").trim() || null;
  } catch {
    /* Kind remains unknown. */
  }
  try {
    argv = procArgv(`${path}/cmdline`);
  } catch {
    /* Kind remains unknown. */
  }
  try {
    const again = readFileSync(`${path}/stat`, "utf8");
    const later = again
      .slice(again.lastIndexOf(") ") + 2)
      .trim()
      .split(" ");
    if (later[19] !== fields[19] || later[0] === "Z" || later[0] === "X")
      return { ...unknown, uid, parentPid: ppid };
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      try {
        statSync(path);
      } catch (second) {
        if (errorCode(second) === "ENOENT")
          return { ...unknown, state: "dead", uid, parentPid: ppid };
      }
    }
    return { ...unknown, uid, parentPid: ppid };
  }
  return {
    state: "live",
    uid,
    identity,
    boot,
    kind: classifyLegacyProcessKind(comm, argv),
    comm,
    argv,
    parentPid: ppid,
  };
};

export const parseLegacySample = (bytes: Buffer): TLegacySample | null => {
  const value = parseStrictDirLockJson(bytes, 8192);
  if (
    !record(value) ||
    !exact(value, SAMPLE_KEYS) ||
    value.version !== 3 ||
    typeof value.domain !== "string" ||
    !isAbsolute(value.domain) ||
    !isGeneration(value.parentGeneration) ||
    typeof value.relativePath !== "string" ||
    value.relativePath.split("/").length > 2 ||
    !value.relativePath
      .split("/")
      .every(
        (part) =>
          part.length > 0 &&
          part !== "." &&
          part !== ".." &&
          Buffer.byteLength(part) <= 255,
      ) ||
    !isGeneration(value.artifactGeneration) ||
    (value.artifactType !== "regular" && value.artifactType !== "directory") ||
    !record(value.artifactEvidence) ||
    !exact(value.artifactEvidence, ["name", "bytes"]) ||
    typeof value.artifactEvidence.name !== "string" ||
    value.artifactEvidence.name.includes("/") ||
    (value.artifactEvidence.bytes !== null &&
      (typeof value.artifactEvidence.bytes !== "string" ||
        decodeDirLockBytes(value.artifactEvidence.bytes) === null)) ||
    (value.artifactType === "regular" &&
      value.artifactEvidence.bytes === null) ||
    (value.artifactType === "directory" &&
      value.artifactEvidence.bytes !== null) ||
    !ROLES.has(value.role as TLegacyArtifact["role"]) ||
    typeof value.pid !== "number" ||
    !validPid(value.pid) ||
    typeof value.capturedIdentity !== "string" ||
    value.capturedIdentity.length > 64 ||
    (value.captureBoot !== null && typeof value.captureBoot !== "string") ||
    !KINDS.has(value.capturedKind as TLegacyProcessKind) ||
    (value.capturedComm !== null && typeof value.capturedComm !== "string")
  )
    return null;
  return value as TLegacySample;
};
export const loadLegacySamples = (hold: TDirectoryHandle): TLegacySample[] => {
  const samples: TLegacySample[] = [];
  for (const name of checkedNames(hold, 162)) {
    if (!SAMPLE_NAME.test(name)) continue;
    const sample = parseLegacySample(readRecord(hold, name, 8192));
    if (sample === null) throw new Error(`invalid legacy sample ${name}`);
    samples.push(sample);
  }
  return samples;
};
export const sameLegacyArtifact = (
  sample: TLegacySample,
  artifact: TLegacyArtifact,
  domain: string,
): boolean =>
  sample.domain === domain &&
  sample.parentGeneration === artifact.parentGeneration &&
  sample.relativePath === artifact.relativePath &&
  sample.artifactGeneration === artifact.artifactGeneration &&
  sample.artifactType === artifact.artifactType &&
  sample.artifactEvidence.name === artifact.artifactEvidence.name &&
  sample.artifactEvidence.bytes === artifact.artifactEvidence.bytes &&
  sample.role === artifact.role &&
  sample.pid === artifact.pid;

/** Called under the metadata gate. Failed reading still persists hold first. */
export const inspectLegacyHold = (
  ctx: TLockControl,
  observe: (pid: number) => TLegacyProcessObservation = observeLegacyProcess,
): void => {
  const held = childExists(ctx.control, "legacy.v3.hold");
  let artifacts: TLegacyArtifact[];
  try {
    artifacts = scanLegacyArtifacts(ctx);
  } catch (error) {
    const hold = ensureDirectory(ctx.control, "legacy.v3.hold");
    close(hold);
    throw error;
  }
  if (!held && artifacts.length === 0) return;
  const hold = ensureDirectory(ctx.control, "legacy.v3.hold");
  try {
    const samples = loadLegacySamples(hold);
    for (const artifact of artifacts) {
      if (
        artifact.pid === null ||
        artifact.artifactGeneration === null ||
        artifact.artifactType === "unknown" ||
        (artifact.artifactType === "regular" &&
          artifact.artifactEvidence.bytes === null)
      )
        continue;
      if (
        samples.some((sample) => sameLegacyArtifact(sample, artifact, ctx.path))
      )
        continue;
      if (samples.length >= 64) {
        const overflow = ensureDirectory(hold, "overflow.v3");
        close(overflow);
        break;
      }
      const observation = observe(artifact.pid);
      const sample: TLegacySample = {
        version: 3,
        domain: ctx.path,
        parentGeneration: artifact.parentGeneration,
        relativePath: artifact.relativePath,
        artifactGeneration: artifact.artifactGeneration,
        artifactType: artifact.artifactType,
        artifactEvidence: artifact.artifactEvidence,
        role: artifact.role,
        pid: artifact.pid,
        capturedIdentity:
          observation.state === "dead"
            ? "dead"
            : (observation.identity ?? "unknown"),
        captureBoot: observation.boot,
        capturedKind: observation.kind,
        capturedComm: observation.comm,
      };
      const nonce = lockNonce();
      writeRecord(
        hold,
        `sample.v3.${nonce}.tmp`,
        `sample.v3.${nonce}.json`,
        JSON.stringify(sample),
      );
      samples.push(sample);
    }
  } finally {
    close(hold);
  }
  throw new LegacyLockError(
    ctx.path,
    artifacts.length ? "legacy artifact observed" : "persisted legacy hold",
  );
};
