/* Header-free declarations: Windows Bun TinyCC has no SDK headers installed. */
typedef unsigned short WCHAR;
typedef WCHAR wchar_t;
typedef unsigned int DWORD;
typedef unsigned int ULONG;
typedef int BOOL;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long intptr_t;
typedef void *HANDLE;
typedef void *PVOID;
typedef void *PSID;
typedef void *PACL;
typedef void *PSECURITY_DESCRIPTOR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef DWORD *LPDWORD;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct { PSID Sid; DWORD Attributes; } SID_AND_ATTRIBUTES;
typedef struct { uint8_t AceType, AceFlags; unsigned short AceSize; } ACE_HEADER;
typedef struct { ACE_HEADER Header; DWORD Mask; uint8_t SidStart[1]; } ACCESS_ALLOWED_ACE;
typedef struct { uint8_t AclRevision, Sbz1; unsigned short AclSize, AceCount, Sbz2; } ACL_HEADER;
typedef struct { BOOL DeleteFile; } FILE_DISPOSITION_INFO;
typedef struct { SID_AND_ATTRIBUTES User; } TOKEN_USER;
typedef struct { DWORD nLength; PVOID lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;
typedef SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;
typedef struct {
  DWORD dwFileAttributes;
  FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
  DWORD dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks;
  DWORD nFileIndexHigh, nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION;
typedef char TAssertPointerWidth[(sizeof(void *) == 8) ? 1 : -1];
typedef char TAssertWideCharWidth[(sizeof(WCHAR) == 2) ? 1 : -1];
typedef char TAssertSecurityAttributesWidth[(sizeof(SECURITY_ATTRIBUTES) == 24) ? 1 : -1];

#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_READ 0x80000000UL
#define GENERIC_WRITE 0x40000000UL
#define OPEN_EXISTING 3
#define CREATE_NEW 1
#define FILE_READ_ATTRIBUTES 0x80
#define FILE_WRITE_ATTRIBUTES 0x100
#define DELETE_ACCESS 0x00010000
#define READ_CONTROL 0x00020000
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define FILE_ATTRIBUTE_NORMAL 0x80
#define SECURITY_SQOS_PRESENT 0x00100000
#define SECURITY_IDENTIFICATION 0x00010000
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000
#define FILE_FLAG_OPEN_REPARSE_POINT 0x00200000
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4
#define PIPE_READMODE_BYTE 0
#define PIPE_NOWAIT 1
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define TOKEN_QUERY 8
#define TokenUser 1
#define ERROR_SUCCESS 0
#define ERROR_INVALID_OWNER 1307
#define ERROR_INVALID_ACL 1336
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_INVALID_PARAMETER 87
#define ERROR_CANT_ACCESS_FILE 1920
#define ERROR_ALREADY_EXISTS 183
#define ERROR_FILE_EXISTS 80
#define ERROR_FILE_TOO_LARGE 223
#define ERROR_GEN_FAILURE 31
#define SDDL_REVISION_1 1
#define SE_FILE_OBJECT 1
#define OWNER_SECURITY_INFORMATION 1
#define DACL_SECURITY_INFORMATION 4
#define PROTECTED_DACL_SECURITY_INFORMATION 0x80000000UL
#define SE_DACL_PROTECTED 0x1000
#define ACCESS_ALLOWED_ACE_TYPE 0
#define FILE_DISPOSITION_INFO_CLASS 4

#define K32 __declspec(dllimport)
#define ADV __declspec(dllimport)
K32 HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE);
K32 HANDLE CreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
K32 BOOL GetNamedPipeServerProcessId(HANDLE, ULONG *);
K32 HANDLE OpenProcess(DWORD, BOOL, DWORD);
K32 BOOL GetProcessTimes(HANDLE, FILETIME *, FILETIME *, FILETIME *, FILETIME *);
K32 BOOL CloseHandle(HANDLE);
K32 BOOL SetNamedPipeHandleState(HANDLE, LPDWORD, LPDWORD, LPDWORD);
K32 BOOL ConnectNamedPipe(HANDLE, PVOID);
K32 BOOL DisconnectNamedPipe(HANDLE);
K32 BOOL ReadFile(HANDLE, PVOID, DWORD, LPDWORD, PVOID);
K32 BOOL WriteFile(HANDLE, const void *, DWORD, LPDWORD, PVOID);
K32 DWORD GetLastError(void);
K32 HANDLE GetCurrentProcess(void);
K32 BOOL GetFileInformationByHandle(HANDLE, BY_HANDLE_FILE_INFORMATION *);
K32 DWORD GetFinalPathNameByHandleW(HANDLE, LPWSTR, DWORD, DWORD);
K32 DWORD GetFullPathNameW(LPCWSTR, DWORD, LPWSTR, LPWSTR *);
K32 BOOL CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
K32 BOOL DeleteFileW(LPCWSTR);
K32 BOOL SetFileInformationByHandle(HANDLE, int, const void *, DWORD);
K32 HANDLE GetProcessHeap(void);
K32 PVOID HeapAlloc(HANDLE, DWORD, uint64_t);
K32 BOOL HeapFree(HANDLE, DWORD, PVOID);
K32 DWORD LocalFree(PVOID);
ADV BOOL OpenProcessToken(HANDLE, DWORD, HANDLE *);
ADV BOOL GetTokenInformation(HANDLE, int, PVOID, DWORD, LPDWORD);
ADV BOOL ConvertSidToStringSidW(PSID, LPWSTR *);
ADV BOOL ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, LPDWORD);
ADV DWORD SetNamedSecurityInfoW(LPWSTR, int, DWORD, PSID, PSID, PACL, PACL);
ADV DWORD SetSecurityInfo(HANDLE, int, DWORD, PSID, PSID, PACL, PACL);
ADV DWORD GetNamedSecurityInfoW(LPWSTR, int, DWORD, PSID *, PSID *, PACL *, PACL *, PSECURITY_DESCRIPTOR *);
ADV DWORD GetSecurityInfo(HANDLE, int, DWORD, PSID *, PSID *, PACL *, PACL *, PSECURITY_DESCRIPTOR *);
ADV BOOL EqualSid(PSID, PSID);
ADV BOOL IsValidAcl(PACL);
ADV BOOL GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, BOOL *, PACL *, BOOL *);
ADV BOOL GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR, unsigned short *, DWORD *);
ADV BOOL GetAce(PACL, DWORD, void **);
ADV BOOL IsValidSid(PSID);

static unsigned int wlen(const WCHAR *s) { unsigned int n = 0; while (s[n]) n++; return n; }
static void wcopy(WCHAR *to, const WCHAR *from) { while ((*to++ = *from++) != 0) {} }
static void wappend(WCHAR *to, const WCHAR *from) { while (*to) to++; wcopy(to, from); }
static void wfromascii(WCHAR *to, const char *from) { while ((*to++ = (WCHAR)(unsigned char)*from++) != 0) {} }
static void wappendascii(WCHAR *to, const char *from) { while (*to) to++; wfromascii(to, from); }
static WCHAR wlower(WCHAR c) { return c >= 'A' && c <= 'Z' ? (WCHAR)(c + 32) : c; }
static DWORD last_error_nonzero(void) { DWORD e = GetLastError(); return e ? e : ERROR_GEN_FAILURE; }
static int wequal(const WCHAR *a, const WCHAR *b) {
  while (*a && *b && wlower(*a) == wlower(*b)) { a++; b++; }
  return *a == *b;
}

/* Status values are returned separately from Win32's thread-local last error. */
static int current_user_sid(PSID *sid, HANDLE *token, void **buffer, DWORD *error);

/* Inspect the ACL on the opened handle so validation cannot be redirected by
   replacing the path after the file or directory was opened. */
static int verify_private_dacl(HANDLE handle, PSID expected_sid, int require_protected, DWORD *error) {
  PSID owner = NULL; PACL dacl = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, NULL, &dacl, NULL, &descriptor);
  if (status != ERROR_SUCCESS) { *error = status; return 0; }
  BOOL present = FALSE, defaulted = FALSE; unsigned short control = 0; DWORD revision = 0;
  if (!EqualSid(expected_sid, owner)) *error = ERROR_INVALID_OWNER;
  else if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl || !IsValidAcl(dacl)) *error = ERROR_INVALID_ACL;
  else if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
      (require_protected && !(control & SE_DACL_PROTECTED))) *error = ERROR_INVALID_ACL;
  else {
    ACL_HEADER *acl = (ACL_HEADER *)dacl;
    if (acl->AceCount == 0) *error = ERROR_INVALID_ACL;
    for (DWORD index = 0; *error == 0 && index < acl->AceCount; index++) {
      void *raw_ace = NULL;
      if (!GetAce(dacl, index, &raw_ace) || raw_ace == NULL) { *error = ERROR_INVALID_ACL; break; }
      ACE_HEADER *header = (ACE_HEADER *)raw_ace;
      if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) { *error = ERROR_INVALID_ACL; break; }
      ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)raw_ace;
      PSID ace_sid = (PSID)&ace->SidStart;
      unsigned int sid_size = 8 + 4 * ((uint8_t *)ace_sid)[1];
      if (sid_size > header->AceSize - 8 || !IsValidSid(ace_sid) || !EqualSid(expected_sid, ace_sid)) *error = ERROR_INVALID_ACL;
    }
  }
  LocalFree(descriptor);
  return *error == 0;
}

static void delete_pinned_file(HANDLE file) {
  FILE_DISPOSITION_INFO disposition; disposition.DeleteFile = TRUE;
  SetFileInformationByHandle(file, FILE_DISPOSITION_INFO_CLASS, &disposition, sizeof(disposition));
}

__declspec(dllexport) int ws_pipe_open(const wchar_t *name, uint32_t expected_pid,
    uint64_t expected_creation, uint64_t *out_handle, uint32_t *out_error) {
  *out_handle = 0;
  *out_error = 0;
  HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
  if (pipe == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); return 0; }
  ULONG server_pid = 0;
  if (!GetNamedPipeServerProcessId(pipe, &server_pid)) {
    *out_error = last_error_nonzero(); CloseHandle(pipe); return 0;
  }
  if (server_pid != expected_pid) {
    *out_error = ERROR_INVALID_OWNER; CloseHandle(pipe); return 0;
  }
  HANDLE server = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
  if (!server) { *out_error = last_error_nonzero(); CloseHandle(pipe); return 0; }
  FILETIME creation, exit_time, kernel_time, user_time;
  int times_ok = GetProcessTimes(server, &creation, &exit_time, &kernel_time, &user_time);
  DWORD time_error = times_ok ? 0 : last_error_nonzero();
  CloseHandle(server);
  uint64_t actual_creation = ((uint64_t)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
  if (!times_ok || actual_creation != expected_creation) {
    *out_error = times_ok ? ERROR_INVALID_OWNER : time_error;
    CloseHandle(pipe); return 0;
  }
  DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
  if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) {
    *out_error = last_error_nonzero(); CloseHandle(pipe); return 0;
  }
  *out_handle = (uint64_t)(uintptr_t)pipe;
  return 1;
}

__declspec(dllexport) int ws_pipe_read(uint64_t raw, void *buffer, uint32_t capacity,
    uint32_t *read_count, uint32_t *out_error) {
  DWORD count = 0; *read_count = 0; *out_error = 0;
  if (ReadFile((HANDLE)(uintptr_t)raw, buffer, capacity, &count, NULL)) {
    *read_count = count; return 1;
  }
    *out_error = last_error_nonzero(); return 0;
}

__declspec(dllexport) int ws_pipe_write(uint64_t raw, const void *buffer, uint32_t length,
    uint32_t *written, uint32_t *out_error) {
  DWORD count = 0; *written = 0; *out_error = 0;
  if (WriteFile((HANDLE)(uintptr_t)raw, buffer, length, &count, NULL)) {
    *written = count; return 1;
  }
  *out_error = last_error_nonzero(); return 0;
}

__declspec(dllexport) int ws_pipe_close(uint64_t raw, uint32_t *out_error) {
  if (CloseHandle((HANDLE)(uintptr_t)raw)) { *out_error = 0; return 1; }
  *out_error = last_error_nonzero(); return 0;
}

__declspec(dllexport) int ws_pipe_connect(uint64_t raw, uint32_t *out_error) {
  if (ConnectNamedPipe((HANDLE)(uintptr_t)raw, 0)) { *out_error = 0; return 1; }
  *out_error = last_error_nonzero(); return 0;
}

__declspec(dllexport) int ws_pipe_disconnect(uint64_t raw, uint32_t *out_error) {
  if (DisconnectNamedPipe((HANDLE)(uintptr_t)raw)) { *out_error = 0; return 1; }
  *out_error = last_error_nonzero(); return 0;
}

__declspec(dllexport) int ws_build_pipe_security(uint8_t *attributes,
    uint64_t *descriptor_out, uint32_t *out_error) {
  *descriptor_out = 0; *out_error = 0;
  PSID sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  if (!current_user_sid(&sid, &token, &token_info, out_error)) return 0;
  LPWSTR sid_text = NULL;
  if (!ConvertSidToStringSidW(sid, &sid_text)) { *out_error = last_error_nonzero(); goto done; }
  wchar_t sddl[256];
  if (wlen(sid_text) + 32 >= 256) { *out_error = ERROR_INVALID_PARAMETER; goto done; }
  wfromascii(sddl, "D:P(A;;GA;;;"); wappend(sddl, sid_text); wappendascii(sddl, ")");
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL)) {
    *out_error = last_error_nonzero(); goto done;
  }
  SECURITY_ATTRIBUTES *sa = (SECURITY_ATTRIBUTES *)attributes;
  sa->nLength = sizeof(*sa); sa->lpSecurityDescriptor = descriptor; sa->bInheritHandle = FALSE;
  *descriptor_out = (uint64_t)(uintptr_t)descriptor;
done:
  if (sid_text) LocalFree(sid_text);
  HeapFree(GetProcessHeap(), 0, token_info); CloseHandle(token);
  return *out_error == 0;
}

__declspec(dllexport) int ws_create_named_pipe(const wchar_t *name, uint32_t open_mode,
    uint32_t pipe_mode, uint32_t max_instances, uint32_t out_size, uint32_t in_size,
    uint32_t timeout, const uint8_t *attributes, uint64_t *out_handle, uint32_t *out_error) {
  *out_handle = 0; *out_error = 0;
  HANDLE handle = CreateNamedPipeW(name, open_mode, pipe_mode, max_instances,
      out_size, in_size, timeout, (LPSECURITY_ATTRIBUTES)attributes);
  if (handle == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); return 0; }
  *out_handle = (uint64_t)(uintptr_t)handle;
  return 1;
}

static int current_user_sid(PSID *sid, HANDLE *token, void **buffer, DWORD *error) {
  *sid = NULL; *token = NULL; *buffer = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)) { *error = last_error_nonzero(); return 0; }
  DWORD needed = 0;
  GetTokenInformation(*token, TokenUser, NULL, 0, &needed);
  DWORD query_error = last_error_nonzero();
  if (query_error != ERROR_INSUFFICIENT_BUFFER || needed == 0) { *error = query_error; CloseHandle(*token); return 0; }
  *buffer = HeapAlloc(GetProcessHeap(), 0, needed);
  if (!*buffer) { *error = ERROR_NOT_ENOUGH_MEMORY; CloseHandle(*token); return 0; }
  if (!GetTokenInformation(*token, TokenUser, *buffer, needed, &needed)) {
    *error = last_error_nonzero(); HeapFree(GetProcessHeap(), 0, *buffer); CloseHandle(*token); return 0;
  }
  *sid = ((TOKEN_USER *)*buffer)->User.Sid;
  return 1;
}

/* Keep large path buffers off the JIT C stack: Windows requires stack probes. */
static int verify_handle_path(HANDLE handle, LPCWSTR path, DWORD *error) {
  WCHAR *storage = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, 3ULL * 32768 * sizeof(WCHAR));
  if (!storage) { *error = ERROR_NOT_ENOUGH_MEMORY; return 0; }
  WCHAR *final_path = storage, *full_path = storage + 32768, *expected = storage + 65536;
  DWORD final_len = GetFinalPathNameByHandleW(handle, final_path, 32768, 0);
  DWORD full_len = GetFullPathNameW(path, 32768, full_path, NULL);
  int ok = 0;
  if (!final_len || final_len >= 32768 || !full_len || full_len >= 32764 ||
      (full_path[0] == '\\' && full_path[1] == '\\')) {
    *error = ERROR_CANT_ACCESS_FILE;
    goto done;
  }
  expected[0] = '\\'; expected[1] = '\\'; expected[2] = '?'; expected[3] = '\\';
  wcopy(expected + 4, full_path);
  unsigned int expected_len = wlen(expected), final_path_len = wlen(final_path);
  while (expected_len > 4 && expected[expected_len - 1] == '\\') expected[--expected_len] = 0;
  while (final_path_len > 4 && final_path[final_path_len - 1] == '\\') final_path[--final_path_len] = 0;
  if (!wequal(final_path, expected)) { *error = ERROR_CANT_ACCESS_FILE; goto done; }
  ok = 1;
done:
  HeapFree(GetProcessHeap(), 0, storage);
  return ok;
}

/* Verify a directory is owned by the current token user and has no reparse bit. */
__declspec(dllexport) int ws_verify_directory_owner(const wchar_t *path, uint32_t *out_error) {
  *out_error = 0;
  HANDLE dir = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (dir == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); return 0; }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(dir, &info)) { *out_error = last_error_nonzero(); CloseHandle(dir); return 0; }
  if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    *out_error = ERROR_CANT_ACCESS_FILE; CloseHandle(dir); return 0;
  }
  if (!verify_handle_path(dir, path, out_error)) { CloseHandle(dir); return 0; }
  PSID expected_sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  if (!current_user_sid(&expected_sid, &token, &token_info, out_error)) { CloseHandle(dir); return 0; }
  verify_private_dacl(dir, expected_sid, 1, out_error);
  HeapFree(GetProcessHeap(), 0, token_info); CloseHandle(token); CloseHandle(dir);
  return *out_error == 0;
}

/* Prevent metadata/marker file links from escaping the verified session directory. */
__declspec(dllexport) int ws_verify_session_file(const wchar_t *path, uint32_t *out_error) {
  *out_error = 0;
  HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); return 0; }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(file, &info)) { *out_error = last_error_nonzero(); CloseHandle(file); return 0; }
  if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || info.nNumberOfLinks != 1) {
    *out_error = ERROR_CANT_ACCESS_FILE; CloseHandle(file); return 0;
  }
  if (!verify_handle_path(file, path, out_error)) { CloseHandle(file); return 0; }
  PSID expected_sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  if (!current_user_sid(&expected_sid, &token, &token_info, out_error)) { CloseHandle(file); return 0; }
  verify_private_dacl(file, expected_sid, 1, out_error);
  HeapFree(GetProcessHeap(), 0, token_info); CloseHandle(token); CloseHandle(file);
  return *out_error == 0;
}

/* Set a protected DACL granting full access to the actual token SID. */
__declspec(dllexport) int ws_secure_directory(const wchar_t *path, uint32_t *out_error) {
  *out_error = 0;
  PSID sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  if (!current_user_sid(&sid, &token, &token_info, out_error)) return 0;
  LPWSTR sid_text = NULL;
  if (!ConvertSidToStringSidW(sid, &sid_text)) { *out_error = last_error_nonzero(); goto done; }
  wchar_t sddl[256];
  if (wlen(sid_text) + 32 >= 256) { *out_error = ERROR_INVALID_PARAMETER; goto done; }
  wfromascii(sddl, "D:P(A;OICI;FA;;;"); wappend(sddl, sid_text); wappendascii(sddl, ")");
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL)) {
    *out_error = last_error_nonzero(); goto done;
  }
  BOOL present = FALSE, defaulted = FALSE; PACL dacl = NULL;
  if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl) {
    *out_error = ERROR_INVALID_ACL; LocalFree(descriptor); goto done;
  }
  HANDLE directory = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL | 0x00040000, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (directory == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); LocalFree(descriptor); goto done; }
  BY_HANDLE_FILE_INFORMATION directory_info;
  if (!GetFileInformationByHandle(directory, &directory_info) ||
      !(directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      !verify_handle_path(directory, path, out_error)) {
    if (*out_error == 0) *out_error = ERROR_CANT_ACCESS_FILE;
    CloseHandle(directory); LocalFree(descriptor); goto done;
  }
  DWORD status = SetSecurityInfo(directory, SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
  if (status != ERROR_SUCCESS) *out_error = status;
  CloseHandle(directory);
  LocalFree(descriptor);
done:
  if (sid_text) LocalFree(sid_text);
  HeapFree(GetProcessHeap(), 0, token_info); CloseHandle(token);
  return *out_error == 0;
}

/* Create only this directory, assigning the token user as owner and inheriting
   its protected private DACL into child files and directories. Never repairs an
   existing path: callers must separately verify an already-present object. */
__declspec(dllexport) int ws_create_session_directory(const wchar_t *path, uint32_t *out_error) {
  *out_error = 0;
  PSID sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  if (!current_user_sid(&sid, &token, &token_info, out_error)) return 0;
  LPWSTR sid_text = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  int ok = 0;
  if (!ConvertSidToStringSidW(sid, &sid_text)) { *out_error = last_error_nonzero(); goto done; }
  wchar_t sddl[256];
  if (2 * wlen(sid_text) + 32 >= 256) { *out_error = ERROR_INVALID_PARAMETER; goto done; }
  wfromascii(sddl, "O:"); wappend(sddl, sid_text);
  wappendascii(sddl, "D:P(A;OICI;FA;;;"); wappend(sddl, sid_text); wappendascii(sddl, ")");
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL)) {
    *out_error = last_error_nonzero(); goto done;
  }
  SECURITY_ATTRIBUTES attributes;
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = descriptor;
  attributes.bInheritHandle = FALSE;
  if (!CreateDirectoryW(path, &attributes)) { *out_error = last_error_nonzero(); goto done; }
  ok = 1;
done:
  if (descriptor) LocalFree(descriptor);
  if (sid_text) LocalFree(sid_text);
  if (token_info) HeapFree(GetProcessHeap(), 0, token_info);
  if (token) CloseHandle(token);
  if (!ok && *out_error == 0) *out_error = ERROR_GEN_FAILURE;
  return ok;
}

/* Create a private file exclusively with its own protected current-user DACL. */
__declspec(dllexport) int ws_create_session_file(const wchar_t *path,
    const uint8_t *content, uint32_t length, uint32_t *out_error) {
  *out_error = 0;
  if (length > 1048576U) { *out_error = ERROR_FILE_TOO_LARGE; return 0; }
  PSID sid = NULL; HANDLE token = NULL; void *token_info = NULL;
  LPWSTR sid_text = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
  HANDLE file = INVALID_HANDLE_VALUE; int ok = 0; int created = 0;
  if (!current_user_sid(&sid, &token, &token_info, out_error)) return 0;
  if (!ConvertSidToStringSidW(sid, &sid_text)) { *out_error = last_error_nonzero(); goto done; }
  WCHAR sddl[256];
  if (2 * wlen(sid_text) + 16 >= 256) { *out_error = ERROR_INVALID_PARAMETER; goto done; }
  wfromascii(sddl, "O:"); wappend(sddl, sid_text);
  wappendascii(sddl, "D:P(A;;FA;;;"); wappend(sddl, sid_text); wappendascii(sddl, ")");
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL)) {
    *out_error = last_error_nonzero(); goto done;
  }
  SECURITY_ATTRIBUTES attributes;
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = descriptor;
  attributes.bInheritHandle = FALSE;
  file = CreateFileW(path, GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE_ACCESS,
      0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) { *out_error = last_error_nonzero(); goto done; }
  created = 1;
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(file, &info)) { *out_error = last_error_nonzero(); goto done; }
  if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || info.nNumberOfLinks != 1) {
    *out_error = ERROR_CANT_ACCESS_FILE; goto done;
  }
  if (!verify_handle_path(file, path, out_error)) goto done;
  uint32_t offset = 0;
  while (offset < length) {
    DWORD wrote = 0; DWORD remaining = length - offset;
    if (!WriteFile(file, content + offset, remaining, &wrote, NULL) || wrote == 0) {
      *out_error = last_error_nonzero(); goto done;
    }
    offset += wrote;
  }
  ok = 1;
done:
  if (file != INVALID_HANDLE_VALUE) { if (!ok && created) delete_pinned_file(file); CloseHandle(file); }
  if (descriptor) LocalFree(descriptor);
  if (sid_text) LocalFree(sid_text);
  if (token_info) HeapFree(GetProcessHeap(), 0, token_info);
  if (token) CloseHandle(token);
  if (!ok && *out_error == 0) *out_error = ERROR_GEN_FAILURE;
  return ok;
}
