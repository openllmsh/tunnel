/* Non-variadic wrappers over variadic libc calls, compiled in Bun with
   TinyCC. bun:ffi binds a fixed signature, but the target ABI passes
   variadic arguments differently (on darwin-arm64 they go on the stack), so
   a bound open/fcntl can see a garbage mode or command argument. Declaring
   the real variadic prototypes here lets the compiler place every argument
   where the ABI expects it. Contract: each wrapper returns the libc result
   when >= 0, otherwise -errno captured inside C right after the call. */

#if defined(LIBC_DARWIN)
extern int *__error(void);
#define LIBC_ERRNO (*__error())
#elif defined(LIBC_LINUX)
extern int *__errno_location(void);
#define LIBC_ERRNO (*__errno_location())
#else
#error "libc-variadic: define LIBC_DARWIN or LIBC_LINUX"
#endif

extern int open(const char *path, int flags, ...);
extern int openat(int dirfd, const char *path, int flags, ...);
extern int fcntl(int fd, int command, ...);
extern int fchmodat(int dirfd, const char *path, int mode, int flag);

int libcOpen(const char *path, int flags, int mode) {
  int result = open(path, flags, mode);
  return result < 0 ? -LIBC_ERRNO : result;
}

int libcOpenat(int dirfd, const char *path, int flags, int mode) {
  int result = openat(dirfd, path, flags, mode);
  return result < 0 ? -LIBC_ERRNO : result;
}

int libcFcntl(int fd, int command, long arg) {
  int result = fcntl(fd, command, arg);
  return result < 0 ? -LIBC_ERRNO : result;
}

int libcFchmodat(int dirfd, const char *path, int mode, int flag) {
  int result = fchmodat(dirfd, path, mode, flag);
  return result < 0 ? -LIBC_ERRNO : result;
}

#ifdef LIBC_LINUX
extern long syscall(long number, ...);
extern int prctl(int option, ...);

long libcSyscall(
    long number,
    long a,
    long b,
    long c,
    long d,
    long e,
    long f
) {
  long result = syscall(number, a, b, c, d, e, f);
  return result < 0 ? -LIBC_ERRNO : result;
}

int libcPrctl(
    int option,
    unsigned long a,
    unsigned long b,
    unsigned long c,
    unsigned long d
) {
  int result = prctl(option, a, b, c, d);
  return result < 0 ? -LIBC_ERRNO : result;
}
#endif
