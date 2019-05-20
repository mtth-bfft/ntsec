#include <Windows.h>
#include "include\timer.h"
#include "include\nt.h"
#include "include\utils.h"

int open_nt_timer_object(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   UNREFERENCED_PARAMETER(pTargetType);
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenTimer(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}