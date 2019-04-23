#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <aclapi.h>
#include "process.h"
#include "registry.h"
#include "token.h"
#include "utils.h"
#include "nt.h"

// This file handles the NT-specific-and-internal aspects
// These structures and functions are mostly undocumented and can change from one release to the next

#define InitializeObjectAttributes( p, n, a, r, s ) { \
   (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
   (p)->RootDirectory = r;                             \
   (p)->Attributes = a;                                \
   (p)->ObjectName = n;                                \
   (p)->SecurityDescriptor = s;                        \
   (p)->SecurityQualityOfService = NULL;               \
   }

typedef struct _OBJECT_DIRECTORY_INFORMATION {
   UNICODE_STRING Name;
   UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
   ULONG           Length;
   HANDLE          RootDirectory;
   PUNICODE_STRING ObjectName;
   ULONG           Attributes;
   PVOID           SecurityDescriptor;
   PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *PNtOpenDirectoryObject)(
   _Out_ PHANDLE            DirectoryHandle,
   _In_  ACCESS_MASK        DesiredAccess,
   _In_  POBJECT_ATTRIBUTES ObjectAttributes);

static PNtOpenDirectoryObject NtOpenDirectoryObject;

int resolve_imports()
{
   int res = 0;

   HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
   if (hNTDLL == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic imports, NTDLL load failed with code '%u'\n"), res);
      goto cleanup;
   }

   NtOpenDirectoryObject = (PNtOpenDirectoryObject)GetProcAddress(hNTDLL, "NtOpenDirectoryObject");
   if (NtOpenDirectoryObject == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import NtOpenDirectoryObject, failed with code '%u'\n"), res);
      goto cleanup;
   }

cleanup:
   return res;
}

UNICODE_STRING* string_to_unicode(PCTSTR swzIn)
{
   PUNICODE_STRING pUS = safe_alloc(sizeof(UNICODE_STRING) + (_tcslen(swzIn) + 1) * sizeof(WCHAR));
   pUS->Length = pUS->MaximumLength = (USHORT)_tcslen(swzIn);
   pUS->Buffer = (PWCHAR)(((PBYTE)pUS) + sizeof(UNICODE_STRING));
#ifdef UNICODE
   memcpy(pUS->Buffer, swzIn, wcslen(swzIn) * sizeof(WCHAR));
#else
   swprintf_s(pUS->Buffer, strlen(swzIn), L"%hs", swzIn);
#endif
   return pUS;
}

int open_target(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   HANDLE hRes = INVALID_HANDLE_VALUE;

   if (targetType == TARGET_PROCESS)
   {
      DWORD dwTargetPID = 0;
      long lPID = 0;
      errno = 0;
      lPID = _tstol(swzTarget);
      if (lPID > 0 && errno == 0)
      {
         dwTargetPID = (DWORD)lPID;
      }
      else
      {
         res = find_process_by_name(swzTarget, &dwTargetPID);
         if (res == ERROR_TOO_MANY_MODULES)
         {
            _ftprintf(stderr, TEXT(" [!] Error: two or more processes found matching '%s'\n"), swzTarget);
            goto cleanup;
         }
         else if (res == ERROR_PATH_NOT_FOUND)
         {
            _ftprintf(stderr, TEXT(" [!] Error: no process found matching '%s'\n"), swzTarget);
            goto cleanup;
         }
      }
      _tprintf(TEXT(" [.] Operating on process %u\n"), dwTargetPID);
      hRes = OpenProcess(dwRightsRequired, FALSE, dwTargetPID);
      if (hRes == NULL)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process %u failed with code %u\n"), dwTargetPID, res);
         goto cleanup;
      }
      *phOut = hRes;
   }
   else if (targetType == TARGET_THREAD)
   {
      DWORD dwTargetTID = 0;
      long lTID = 0;
      errno = 0;
      lTID = _tstol(swzTarget);
      if (lTID <= 0 || errno != 0)
      {
         if (_tcsicmp(swzTarget, TEXT("current")) == 0)
         {
         lTID = GetCurrentThreadId();
         }
         else
         {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: option --thread requires a positive TID\n"));
         goto cleanup;
         }
      }
      dwTargetTID = (DWORD)lTID;
      _tprintf(TEXT(" [.] Operating on thread %u\n"), (DWORD)lTID);
      hRes = OpenThread(dwRightsRequired, FALSE, dwTargetTID);
      if (hRes == NULL)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening thread %u failed with code %u\n"), dwTargetTID, res);
         goto cleanup;
      }
      *phOut = hRes;
   }
   else if (targetType == TARGET_REGKEY)
   {
      res = open_regkey_by_name(swzTarget, dwRightsRequired, (PHKEY)phOut);
      if (res == 0)
         _tprintf(TEXT(" [.] Operating on registry key %s\n"), swzTarget);
   }
   else if (targetType == TARGET_FILE)
   {
      hRes = CreateFile(swzTarget, dwRightsRequired, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
      if (hRes == INVALID_HANDLE_VALUE)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: unable to open file or directory '%s', error code %u\n"), swzTarget, res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on file object %s\n"), swzTarget);
      *phOut = hRes;
   }
   else if (targetType == TARGET_PRIMARY_TOKEN)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
         goto cleanup;
      if (!OpenProcessToken(hProcess, dwRightsRequired, phOut))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process token failed with code %u\n"), res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on primary token\n"));
   }
   else if (targetType == TARGET_IMPERSONATION_TOKEN)
   {
      HANDLE hThread = INVALID_HANDLE_VALUE;
      res = open_target(swzTarget, TARGET_THREAD, THREAD_QUERY_INFORMATION, &hThread);
      if (res != 0)
         goto cleanup;
      if (!OpenThreadToken(hThread, dwRightsRequired, TRUE, phOut))
      {
         res = GetLastError();
         if (res == ERROR_NO_TOKEN)
            _ftprintf(stderr, TEXT(" [!] Error: thread is not impersonating, there is no token to open\n"));
         else
            _ftprintf(stderr, TEXT(" [!] Error: opening thread token failed with code %u\n"), res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on impersonation token\n"));
   }
   else if (targetType == TARGET_KERNEL_OBJECT)
   {
      res = open_kernel_object(swzTarget, dwRightsRequired, phOut);
      if (res == 0)
         _tprintf(TEXT(" [.] Operating on kernel object %s\n"), swzTarget);
   }
   else
   {
      _ftprintf(stderr, TEXT(" [!] Error: no target selected, cannot apply operation\n"));
      res = ERROR_INVALID_PARAMETER;
   }

cleanup:
   return res;
}


int open_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenDirectoryObject(phOut, dwRightsRequired, &objAttr);
   if (status != STATUS_SUCCESS)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: opening NT directory object '%s' failed with status 0x%08X\n"), swzNTPath, res);
   }
   return res;
}

int open_kernel_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   SIZE_T dwNTPathLen = 0;

   if (swzNTPath == NULL || *swzNTPath != TEXT('\\'))
   {
      _ftprintf(stderr, TEXT(" [!] Error: for kernel objects, an absolute NT path is required.\n"));
      res = ERROR_INVALID_PARAMETER;
   }

   dwNTPathLen = _tcslen(swzNTPath);
   if (swzNTPath[dwNTPathLen - 1] == TEXT('\\'))
   {
      res = open_directory_object(swzNTPath, dwRightsRequired, phOut);
   }
   else
   {
      printf(" Not implemented yet, work in progress ");
      return -1;
   }

   return res;
}

int do_show_sd(target_t targetType, PCTSTR swzTarget, BOOL bVerbose)
{
   int res = 0;
   DWORD dwRes = 0;
   HANDLE hTarget = INVALID_HANDLE_VALUE;
   DWORD dwOpenRights = READ_CONTROL;
   DWORD dwSDFlags = ATTRIBUTE_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
   PSECURITY_DESCRIPTOR pSD = NULL;

   // Dump SACL information, only possible when privileged enough
   if (has_privilege_caller(SE_SECURITY_NAME))
   {
      dwOpenRights |= ACCESS_SYSTEM_SECURITY;
      dwSDFlags |= SACL_SECURITY_INFORMATION;
      set_privilege_caller(SE_SECURITY_NAME, TRUE);
   }

   res = open_target(swzTarget, targetType, dwOpenRights, &hTarget);
   if (res != 0)
      goto cleanup;

   dwRes = GetSecurityInfo(hTarget, SE_KERNEL_OBJECT, dwSDFlags, NULL, NULL, NULL, NULL, &pSD);
   if (dwRes != ERROR_SUCCESS)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: unable to query security descriptor (error %u)\n"), res);
      goto cleanup;
   }

   if (bVerbose)
      res = print_sd(pSD, dwSDFlags);
   else
      res = print_sddl(pSD, dwSDFlags);

cleanup:
   if (pSD != NULL)
      LocalFree(pSD);
   return res;
}

int get_target_token(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phToken)
{
   int res = 0;
   HANDLE hTarget = INVALID_HANDLE_VALUE;

   if (targetType == TARGET_PRIMARY_TOKEN || targetType == TARGET_PROCESS)
   {
      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hTarget);
      if (res != 0)
         goto cleanup;
      if (!OpenProcessToken(hTarget, dwRightsRequired, phToken))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process token failed with code %u\n"), res);
         goto cleanup;
      }
   }
   else if (targetType == TARGET_IMPERSONATION_TOKEN || targetType == TARGET_THREAD)
   {
      res = open_target(swzTarget, TARGET_THREAD, THREAD_QUERY_INFORMATION, &hTarget);
      if (res != 0)
         goto cleanup;
      if (!OpenThreadToken(hTarget, dwRightsRequired, TRUE, phToken))
      {
         res = GetLastError();
         if (res == ERROR_NO_TOKEN)
            _ftprintf(stderr, TEXT(" [!] Error: target thread is not impersonating, no token to open\n"));
         else
            _ftprintf(stderr, TEXT(" [!] Error: opening thread token failed with code %u\n"), res);
         goto cleanup;
      }
   }
   else
   {
      res = ERROR_INVALID_PARAMETER;
      _ftprintf(stderr, TEXT(" [!] Error: cannot open target, target selected must be a process or thread\n"));
      goto cleanup;
   }

   cleanup:
   return res;
}
