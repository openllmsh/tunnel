#ifdef __APPLE__
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <unistd.h>

#ifndef KERN_PROCARGS2
#define KERN_PROCARGS2 49
#endif

/* Return count; caller supplies 32769 slots to detect overflow. */
int dl_list_pids(int *out, int capacity) {
  if (!out || capacity < 1 || capacity > 32769) return -1;
  return proc_listallpids(out, capacity * (int)sizeof(int));
}

/* Fixed little-endian Darwin x64/arm64 wire: uid, ppid, status,
   start seconds, start microseconds, and 16-byte comm. */
int dl_proc_snapshot(int pid, unsigned char *out, int capacity) {
  if (!out || capacity < 44 || pid <= 0) return -1;
  struct proc_bsdinfo info;
  memset(&info, 0, sizeof(info));
  errno = 0;
  int length = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
  if (length != (int)sizeof(info)) return errno == ESRCH ? 0 : -1;
  uint32_t uid = info.pbi_uid, ppid = info.pbi_ppid, status = info.pbi_status;
  memcpy(out, &uid, 4); memcpy(out + 4, &ppid, 4); memcpy(out + 8, &status, 4);
  memcpy(out + 12, &info.pbi_start_tvsec, 8);
  memcpy(out + 20, &info.pbi_start_tvusec, 8);
  memcpy(out + 28, info.pbi_comm, 16);
  return 44;
}

/* Preserve argv boundaries and discard executable-path, environment, apple[]. */
int dl_proc_argv(int pid, unsigned char *out, int capacity) {
  if (!out || capacity < 1 || capacity > 1048576 || pid <= 0) return -1;
  int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
  size_t length = (size_t)capacity;
  unsigned char *buffer = malloc(length);
  if (!buffer) return -1;
  int result = -1;
  if (sysctl(mib, 3, buffer, &length, NULL, 0) != 0 || length < sizeof(int)) goto done;
  int argc;
  memcpy(&argc, buffer, sizeof(int));
  if (argc < 1 || argc > 65536) goto done;
  size_t at = sizeof(int);
  while (at < length && buffer[at] != 0) at++;
  if (at == length) goto done;
  while (at < length && buffer[at] == 0) at++;
  size_t written = 0;
  for (int i = 0; i < argc; i++) {
    size_t start = at;
    while (at < length && buffer[at] != 0) at++;
    if (at == length || written + at - start + 1 > (size_t)capacity) goto done;
    memcpy(out + written, buffer + start, at - start + 1);
    written += at - start + 1;
    at++;
  }
  result = (int)written;
done:
  free(buffer);
  return result;
}
#endif
