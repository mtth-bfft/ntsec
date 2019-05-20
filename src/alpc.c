#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\alpc.h"
#include "include\utils.h"
#include "include\nt.h"
#include "include\directory.h"

int open_nt_alpcconnectionport_object(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   UNREFERENCED_PARAMETER(pTargetType);
   int res = 0;
   NTSTATUS status = 0;
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);
   OBJECT_ATTRIBUTES objAttr = { 0 };
   LARGE_INTEGER liTimeout = { 0 };
   ULONG ulBufferLen = 0;
   DWORD dwGrantedRights = 0;

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
   liTimeout.QuadPart = 1;
   //TODO: see http://alex-ionescu.com/publications/SyScan/syscan2014.pdf slide 18 for actual connection parameters
   status = NtAlpcConnectPort(phOut, pUSObjName, &objAttr, NULL, 0, NULL, NULL, &ulBufferLen, NULL, NULL, &liTimeout);
   if (!NT_SUCCESS(res))
   {
      res = status;
      goto cleanup;
   }

   if ((dwRightsRequired & MAXIMUM_ALLOWED) == 0)
   {
      res = get_handle_granted_rights(*phOut, &dwGrantedRights);
      if (res != 0)
         goto cleanup;

      if ((dwGrantedRights & dwRightsRequired) != dwRightsRequired)
         res = ERROR_ACCESS_DENIED;
   }

cleanup:
   if (res != 0 && *phOut != NULL && *phOut != INVALID_HANDLE_VALUE)
      CloseHandle(*phOut);
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

static int nt_obj_callback(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   int res = 0;
   HANDLE hALPC = INVALID_HANDLE_VALUE;
   target_t targetType = TARGET_ALPC_CONNECTION_PORT;

   if (_wcsnicmp(L"ALPC Port", usObjType->Buffer, usObjType->Length) != 0)
      return 0;

   res = open_nt_alpcconnectionport_object(swzNTPath, &targetType, *(PDWORD)pData, &hALPC);
   if (res == 0)
   {
      _tprintf(TEXT(" %s\n"), swzNTPath);
      CloseHandle(hALPC);
   }
   else
   {
      _ftprintf(stderr, TEXT(" [!] Warning: opening ALPC connection port %s failed with code %u\n"), swzNTPath, res);
   }

   // Always continue enumerating
   return 0;
}

int enumerate_alpc_ports_with(DWORD dwDesiredAccess)
{
   return foreach_nt_object(TEXT("\\"), &nt_obj_callback, (PVOID)&dwDesiredAccess, TRUE);
}