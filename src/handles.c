#include <Windows.h>
#include "handles.h"
#include "nt.h"
#include "utils.h"

int get_handle_granted_rights(HANDLE hHandle, PDWORD pdwGrantedRights)
{
   int res = 0;
   NTSTATUS status = 0;
   ULONG ulBufRequired = 0;
   ULONG ulBufLen = 0x1000;
   PSYSTEM_HANDLE_INFORMATION pHandles = safe_alloc(ulBufLen);
   BOOL bFound = FALSE;

   if (pdwGrantedRights == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   do
   {
      ulBufLen *= 2;
      pHandles = safe_realloc(pHandles, ulBufLen);
      status = NtQuerySystemInformation(SystemHandleInformation, pHandles, ulBufLen, &ulBufRequired);
      // NtQuerySystemInformation(SystemHandleInformation) doesn't fill ulBufRequired: try again with a higher guess...
   } while (status == STATUS_INFO_LENGTH_MISMATCH);

   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

   for (ULONG i = 0; i < pHandles->HandleCount; i++)
   {
      PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = &(pHandles->Handles[i]);
      if (pHandle->ProcessId == GetCurrentProcessId() && (SIZE_T)pHandle->Handle == (SIZE_T)hHandle)
      {
         bFound = TRUE;
         *pdwGrantedRights = pHandle->GrantedAccess;
         break;
      }
   }

   if (!bFound)
      res = ERROR_NOT_FOUND;

cleanup:
   safe_free(pHandles);
   return res;
}
