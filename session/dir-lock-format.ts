/** Frozen v3 directory-lock wire grammar. No filesystem operations belong here. */
import { Buffer } from "node:buffer";

export const DIR_LOCK_LIMITS = {
  lockNameBytes: 160,
  basenameBytes: 255,
  ownerBytes: 1024,
  planBytes: 8192,
} as const;

export type TDirLockKind = "e" | "u" | "r" | "v" | "a";
export type TDirLockOperation = "p" | "s" | "l" | "t";
export type TDirLockActor = {
  readonly pid: number;
  readonly start: string;
  readonly nonce: string;
};
export type TDirLockClaim = TDirLockActor & { readonly kind: TDirLockKind };
export type TDirLockOwnerRecord = TDirLockClaim & { readonly version: 3 };
export type TDirLockPlan = {
  readonly version: 3;
  readonly operation: TDirLockOperation;
  readonly target: string;
  readonly generation: string;
  readonly basis: "absent" | "dead" | "cancelled" | "released" | "restore";
  readonly claim: TDirLockClaim | null;
  readonly ownerBytes: string | null;
  readonly ageMtimeMs: string | null;
};
export type TDirLockTransaction = {
  readonly kind: TDirLockKind;
  readonly operation: TDirLockOperation;
  readonly actor: TDirLockActor;
  readonly generation: string;
};
export type TDirLockArtifactScope =
  | "child"
  | "sibling"
  | "launch"
  | "legacy-env"
  | "legacy-vendor"
  | "control";
export type TDirLockArtifactClass = "new" | "legacy" | "outside";

const KINDS = new Set<string>(["e", "u", "r", "v", "a"]);
const OPERATIONS = new Set<string>(["p", "s", "l", "t"]);
const BASES = new Set<string>([
  "absent",
  "dead",
  "cancelled",
  "released",
  "restore",
]);
const NONCE = /^[0-9a-f]{32}$/;
const PID = /^[1-9][0-9]{0,9}$/;
const GENERATION = /^([0-9a-f]{16})\.([0-9a-f]{16})$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const MAX_U64 = (1n << 64n) - 1n;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const ownRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const hasExactKeys = (
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean =>
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const isKind = (value: unknown): value is TDirLockKind =>
  typeof value === "string" && KINDS.has(value);
const isOperation = (value: unknown): value is TDirLockOperation =>
  typeof value === "string" && OPERATIONS.has(value);
const isBasename = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value !== "." &&
  value !== ".." &&
  !value.includes("/") &&
  !value.includes("\0") &&
  Buffer.byteLength(value, "utf8") <= DIR_LOCK_LIMITS.basenameBytes &&
  Buffer.from(value, "utf8").toString("utf8") === value;
const isLockName = (value: unknown): value is string =>
  isBasename(value) &&
  Buffer.byteLength(value, "utf8") <= DIR_LOCK_LIMITS.lockNameBytes;
const isPid = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isInteger(value) &&
  value > 0 &&
  value <= 2147483647;
const parsePid = (value: string): number | null => {
  if (!PID.test(value)) return null;
  const pid = Number(value);
  return isPid(pid) ? pid : null;
};
const isStart = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length >= 1 &&
  value.length <= 64 &&
  /^[\x20-\x7e]+$/.test(value) &&
  value.trim() === value &&
  !/\s{2}/.test(value);
const isNonce = (value: unknown): value is string =>
  typeof value === "string" && NONCE.test(value);
const isActor = (value: unknown): value is TDirLockActor =>
  ownRecord(value) &&
  isPid(value.pid) &&
  isStart(value.start) &&
  isNonce(value.nonce);
const isClaim = (value: unknown): value is TDirLockClaim =>
  ownRecord(value) &&
  hasExactKeys(value, ["kind", "pid", "start", "nonce"]) &&
  isKind(value.kind) &&
  isPid(value.pid) &&
  isStart(value.start) &&
  isNonce(value.nonce);
const assertBasename = (name: string): void => {
  if (!isBasename(name)) throw new Error("invalid directory-lock basename");
};

/** Canonical RFC 4648 base64url, with no padding. */
export const encodeDirLockBytes = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");
export const decodeDirLockBytes = (value: string): Uint8Array | null => {
  if (typeof value !== "string" || !BASE64URL.test(value)) return null;
  const bytes = Buffer.from(value, "base64url");
  return encodeDirLockBytes(bytes) === value ? bytes : null;
};

export const encodeDirLockActor = (actor: TDirLockActor): string => {
  if (!isActor(actor)) throw new Error("invalid directory-lock actor");
  return encodeDirLockBytes(
    Buffer.from(`${actor.pid}\n${actor.start}\n${actor.nonce}`, "utf8"),
  );
};
export const decodeDirLockActor = (token: string): TDirLockActor | null => {
  const bytes = decodeDirLockBytes(token);
  if (bytes === null) return null;
  let payload: string;
  try {
    payload = utf8Decoder.decode(bytes);
  } catch {
    return null;
  }
  const parts = payload.split("\n");
  if (parts.length !== 3) return null;
  const pid = parsePid(parts[0] ?? "");
  const actor = { pid, start: parts[1], nonce: parts[2] };
  return isActor(actor) ? actor : null;
};

export const formatDirLockGeneration = (
  device: bigint,
  inode: bigint,
): string => {
  if (device < 0n || device > MAX_U64 || inode < 0n || inode > MAX_U64)
    throw new Error("directory-lock generation overflow");
  return `${device.toString(16).padStart(16, "0")}.${inode.toString(16).padStart(16, "0")}`;
};
export const parseDirLockGeneration = (
  value: string,
): { readonly device: bigint; readonly inode: bigint } | null => {
  const match = GENERATION.exec(value);
  if (match === null) return null;
  return { device: BigInt(`0x${match[1]}`), inode: BigInt(`0x${match[2]}`) };
};

/** Validate duplicate keys at every depth before JSON.parse can discard them. */
const hasDuplicateJsonKeys = (source: string): boolean => {
  let index = 0;
  const skip = (): void => {
    while (/\s/.test(source[index] ?? "") && index < source.length) index++;
  };
  const stringToken = (): string => {
    const begin = index++;
    while (index < source.length) {
      if (source[index] === "\\") {
        index += 2;
        continue;
      }
      if (source[index++] === '"')
        return JSON.parse(source.slice(begin, index)) as string;
    }
    throw new Error("unterminated JSON string");
  };
  const value = (depth: number): boolean => {
    if (depth > 32) throw new Error("JSON nesting too deep");
    skip();
    const current = source[index];
    if (current === '"') {
      stringToken();
      return false;
    }
    if (current === "{") {
      index++;
      skip();
      const keys = new Set<string>();
      let duplicate = false;
      if (source[index] === "}") {
        index++;
        return false;
      }
      while (index < source.length) {
        if (source[index] !== '"') throw new Error("invalid JSON object");
        const key = stringToken();
        duplicate ||= keys.has(key);
        keys.add(key);
        skip();
        if (source[index++] !== ":") throw new Error("invalid JSON object");
        duplicate = value(depth + 1) || duplicate;
        skip();
        const delimiter = source[index++];
        if (delimiter === "}") return duplicate;
        if (delimiter !== ",") throw new Error("invalid JSON object");
        skip();
      }
      throw new Error("unterminated JSON object");
    }
    if (current === "[") {
      index++;
      skip();
      if (source[index] === "]") {
        index++;
        return false;
      }
      let duplicate = false;
      while (index < source.length) {
        duplicate = value(depth + 1) || duplicate;
        skip();
        const delimiter = source[index++];
        if (delimiter === "]") return duplicate;
        if (delimiter !== ",") throw new Error("invalid JSON array");
      }
      throw new Error("unterminated JSON array");
    }
    const remainder = source.slice(index);
    const primitive =
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
        remainder,
      );
    if (primitive === null) throw new Error("invalid JSON value");
    index += primitive[0].length;
    return false;
  };
  const duplicate = value(0);
  skip();
  if (index !== source.length) throw new Error("trailing JSON data");
  return duplicate;
};

const parseStrictJson = (
  input: Uint8Array | string,
  maxBytes: number,
): unknown | null => {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  if (bytes.byteLength > maxBytes) return null;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return null;
  let source: string;
  try {
    source = utf8Decoder.decode(bytes);
    if (typeof input === "string" && source !== input) return null;
    if (hasDuplicateJsonKeys(source)) return null;
    return JSON.parse(source) as unknown;
  } catch {
    return null;
  }
};

export const parseDirLockOwnerRecord = (
  input: Uint8Array | string,
): TDirLockOwnerRecord | null => {
  const value = parseStrictJson(input, DIR_LOCK_LIMITS.ownerBytes);
  if (
    !ownRecord(value) ||
    !hasExactKeys(value, ["version", "kind", "pid", "start", "nonce"]) ||
    value.version !== 3 ||
    !isKind(value.kind) ||
    !isPid(value.pid) ||
    !isStart(value.start) ||
    !isNonce(value.nonce)
  )
    return null;
  return {
    version: 3,
    kind: value.kind,
    pid: value.pid,
    start: value.start,
    nonce: value.nonce,
  };
};
export const serializeDirLockOwnerRecord = (claim: TDirLockClaim): string => {
  if (!isClaim(claim)) throw new Error("invalid directory-lock claim");
  const encoded = JSON.stringify({
    version: 3,
    kind: claim.kind,
    pid: claim.pid,
    start: claim.start,
    nonce: claim.nonce,
  });
  if (Buffer.byteLength(encoded) > DIR_LOCK_LIMITS.ownerBytes)
    throw new Error("owner record too large");
  return encoded;
};

export const parseDirLockPlan = (
  input: Uint8Array | string,
): TDirLockPlan | null => {
  const value = parseStrictJson(input, DIR_LOCK_LIMITS.planBytes);
  if (
    !ownRecord(value) ||
    !hasExactKeys(value, [
      "version",
      "operation",
      "target",
      "generation",
      "basis",
      "claim",
      "ownerBytes",
      "ageMtimeMs",
    ]) ||
    value.version !== 3 ||
    !isOperation(value.operation) ||
    !isBasename(value.target) ||
    typeof value.generation !== "string" ||
    parseDirLockGeneration(value.generation) === null ||
    typeof value.basis !== "string" ||
    !BASES.has(value.basis) ||
    (value.claim !== null && !isClaim(value.claim)) ||
    (value.ownerBytes !== null &&
      (typeof value.ownerBytes !== "string" ||
        decodeDirLockBytes(value.ownerBytes) === null)) ||
    (value.ageMtimeMs !== null &&
      (typeof value.ageMtimeMs !== "string" ||
        !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(value.ageMtimeMs)))
  )
    return null;
  if (
    value.basis === "absent"
      ? value.claim !== null || value.ownerBytes !== null
      : value.claim === null
  )
    return null;
  return value as TDirLockPlan;
};
export const serializeDirLockPlan = (plan: TDirLockPlan): string => {
  const encoded = JSON.stringify(plan);
  if (parseDirLockPlan(encoded) === null)
    throw new Error("invalid directory-lock plan");
  return encoded;
};

export const formatDirLockControlName = (lockName: string): string => {
  if (!isLockName(lockName)) throw new Error("invalid directory-lock name");
  const name = `.openllm-lock.v3.${encodeDirLockBytes(Buffer.from(lockName, "utf8"))}`;
  assertBasename(name);
  return name;
};
export const parseDirLockControlName = (name: string): string | null => {
  const match = /^\.openllm-lock\.v3\.([A-Za-z0-9_-]+)$/.exec(name);
  if (match === null) return null;
  const bytes = decodeDirLockBytes(match[1] ?? "");
  if (bytes === null) return null;
  try {
    const lockName = utf8Decoder.decode(bytes);
    return isLockName(lockName) && formatDirLockControlName(lockName) === name
      ? lockName
      : null;
  } catch {
    return null;
  }
};

export const formatDirLockTransactionName = (
  transaction: TDirLockTransaction,
): string => {
  if (
    !isKind(transaction.kind) ||
    !isOperation(transaction.operation) ||
    parseDirLockGeneration(transaction.generation) === null
  )
    throw new Error("invalid directory-lock transaction");
  const name = `t.v3.${transaction.kind}.${transaction.operation}.${encodeDirLockActor(transaction.actor)}.${transaction.generation}`;
  assertBasename(name);
  return name;
};
export const parseDirLockTransactionName = (
  name: string,
): TDirLockTransaction | null => {
  const parts = name.split(".");
  if (parts.length !== 7 || parts[0] !== "t" || parts[1] !== "v3") return null;
  const kind = parts[2];
  const operation = parts[3];
  const actor = decodeDirLockActor(parts[4] ?? "");
  const generation = `${parts[5]}.${parts[6]}`;
  if (
    !isKind(kind) ||
    !isOperation(operation) ||
    actor === null ||
    parseDirLockGeneration(generation) === null
  )
    return null;
  return { kind, operation, actor, generation };
};

/** Classify only entries of the caller's exact configured namespace. */
export const classifyDirLockArtifact = (
  name: string,
  scope: TDirLockArtifactScope,
  configuredPrefix?: string,
): TDirLockArtifactClass => {
  if (!isBasename(name)) return "outside";
  if (scope === "control") {
    if (configuredPrefix === undefined || !isLockName(configuredPrefix))
      return "outside";
    return name === formatDirLockControlName(configuredPrefix)
      ? "new"
      : "outside";
  }
  if (
    (scope === "legacy-env" || scope === "legacy-vendor") &&
    name === configuredPrefix
  ) {
    return "legacy";
  }
  let portion = name;
  if (scope !== "child") {
    if (
      configuredPrefix === undefined ||
      !name.startsWith(`${configuredPrefix}.`)
    )
      return "outside";
    portion = name.slice(configuredPrefix.length + 1);
    if (
      scope === "launch" &&
      portion !== "launch" &&
      !portion.startsWith("launch.")
    )
      return "outside";
    if (
      scope === "sibling" &&
      !/^(?:steal-|rel-|stealing-|releasing-|stealing\.|releasing\.)/.test(
        portion,
      )
    )
      return "outside";
    if (scope === "legacy-env" && !/^(?:stale\.|rel\.)/.test(portion))
      return "outside";
    if (scope === "legacy-vendor" && !/^(?:parked-|tmp\.)/.test(portion))
      return "outside";
  }
  return portion.split(".").includes("v3") ? "new" : "legacy";
};
