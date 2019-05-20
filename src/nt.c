#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\nt.h"
#include "include\utils.h"
#include "include\directory.h"
#include "include\targets.h"

typedef struct {
   PCTSTR swzNTPath;
   BOOL bFound;
   target_t type;
} nt_object_lookup_t;

PNtOpenDirectoryObject NtOpenDirectoryObject = NULL;
PNtQueryDirectoryObject NtQueryDirectoryObject = NULL;
PNtCreateFile NtCreateFile = NULL;
PNtQueryDirectoryFile NtQueryDirectoryFile = NULL;
PNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject = NULL;
PNtOpenMutant NtOpenMutant = NULL;
PNtOpenEvent NtOpenEvent = NULL;
PNtOpenKeyedEvent NtOpenKeyedEvent = NULL;
PNtOpenSection NtOpenSection = NULL;
PNtOpenSemaphore NtOpenSemaphore = NULL;
PNtOpenTimer NtOpenTimer = NULL;
PNtOpenSession NtOpenSession = NULL;
PNtOpenJobObject NtOpenJobObject = NULL;
PNtOpenPartition NtOpenPartition = NULL;
PNtOpenKeyEx NtOpenKeyEx = NULL;
PNtEnumerateKey NtEnumerateKey = NULL;
PNtAlpcConnectPort NtAlpcConnectPort = NULL;
PNtQuerySystemInformation NtQuerySystemInformation = NULL;
PNtQueryObject NtQueryObject = NULL;

static int do_import_function(HMODULE hLib, PCSTR swzFunctionName, PVOID pFunctionPtr)
{
   int res = 0;
   PVOID pRes = NULL;

   if (hLib == NULL || hLib == INVALID_HANDLE_VALUE || swzFunctionName == NULL || pFunctionPtr == NULL || *(PVOID*)pFunctionPtr != NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   pRes = (PVOID)GetProcAddress(hLib, swzFunctionName);
   if (pRes == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import '%hs', failed with code %u\n"), swzFunctionName, res);
      goto cleanup;
   }
   *(PVOID*)pFunctionPtr = pRes;

cleanup:
   return res;
}

int resolve_imports()
{
   int res = 0;

   HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
   if (hNTDLL == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic imports, NTDLL load failed with code %u\n"), res);
      goto cleanup;
   }
   res = do_import_function(hNTDLL, "NtOpenDirectoryObject", &NtOpenDirectoryObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQueryDirectoryObject", &NtQueryDirectoryObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtCreateFile", &NtCreateFile);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQueryDirectoryFile", &NtQueryDirectoryFile);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSymbolicLinkObject", &NtOpenSymbolicLinkObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenMutant", &NtOpenMutant);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenEvent", &NtOpenEvent);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenKeyedEvent", &NtOpenKeyedEvent);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSection", &NtOpenSection);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSemaphore", &NtOpenSemaphore);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenTimer", &NtOpenTimer);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSession", &NtOpenSession);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenJobObject", &NtOpenJobObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenPartition", &NtOpenPartition);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenKeyEx", &NtOpenKeyEx);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtEnumerateKey", &NtEnumerateKey);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtAlpcConnectPort", &NtAlpcConnectPort);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQuerySystemInformation", &NtQuerySystemInformation);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQueryObject", &NtQueryObject);
   if (res != 0)
      goto cleanup;

cleanup:
   return res;
}

static int callback_find_nt_object_type(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   int res = 0;
   nt_object_lookup_t *pLookup = (nt_object_lookup_t*)pData;

   if (_tcscmp(swzNTPath, pLookup->swzNTPath) == 0)
   {
      res = lookup_type_id(usObjType->Buffer, usObjType->Length, &(pLookup->type));
      if (res != 0)
         _ftprintf(stderr, TEXT(" [!] Warning: object '%s' type lookup failed with code %u\n"),
            swzNTPath, res);
      pLookup->bFound = TRUE;
      // Stop enumerating in all cases
      return 1;
   }
   else
   {
      return 0;
   }
}

int get_nt_object_type(PCTSTR swzNTPath, target_t *pType)
{
   int res = 0;
   SIZE_T dwNTPathLen = 0;
   PTSTR swzNTDirPath = NULL;
   nt_object_lookup_t lookup = { 0 };

   if (swzNTPath == NULL || pType == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }
   else if (*swzNTPath != TEXT('\\'))
   {
      _ftprintf(stderr, TEXT(" [!] Invalid parameter: for NT objects, an absolute NT path is required\n"));
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   dwNTPathLen = _tcslen(swzNTPath);
   if (swzNTPath[dwNTPathLen - 1] == TEXT('\\'))
   {
      *pType = TARGET_DIRECTORY_OBJECT;
      goto cleanup;
   }
   else
   {
      lookup.bFound = FALSE;
      lookup.swzNTPath = swzNTPath;
      swzNTDirPath = safe_strdup(swzNTPath);
      basedir(swzNTDirPath);
      foreach_nt_object(swzNTDirPath, callback_find_nt_object_type, &lookup, FALSE);
      if (!lookup.bFound)
      {
         //_ftprintf(stderr, TEXT(" [!] Object '%s' not found in %s\n"), swzNTPath, swzNTDirPath);
         res = ERROR_NOT_FOUND;
         goto cleanup;
      }
      *pType = lookup.type;
      //_tprintf(TEXT(" [.] Operating on NT object %s of type %s\n"), swzNTPath, lookup.swzType);
   }

cleanup:
   if (swzNTDirPath != NULL)
      safe_free(swzNTDirPath);
   return res;
}
