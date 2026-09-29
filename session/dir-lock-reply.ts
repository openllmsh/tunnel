import {
  closeSync,
  fsyncSync,
  linkSync,
  openSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { lockNonce } from "./dir-lock-control";
import { posixOpenFlags } from "./dir-lock-fs";

export const writeLockReply = (
  path: string,
  code: number,
  nonce?: string | null,
): void => {
  if (!isAbsolute(path) || path.includes("\0"))
    throw new TypeError("invalid lock reply path");
  const flags = posixOpenFlags();
  const temporary = `${path}.v3.${lockNonce()}.tmp`;
  const fd = openSync(
    temporary,
    flags.O_WRONLY |
      flags.O_CREAT |
      flags.O_EXCL |
      flags.O_NOFOLLOW |
      flags.O_CLOEXEC,
    0o600,
  );
  try {
    try {
      writeFileSync(fd, `${JSON.stringify({ version: 3, code, nonce })}\n`);
      fsyncSync(fd);
    } catch (error) {
      try {
        closeSync(fd);
      } catch {
        // Keep the write error.
      }
      throw error;
    }
    closeSync(fd);
    linkSync(temporary, path);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
      // Keep the published reply or the original error.
    }
  }
};
