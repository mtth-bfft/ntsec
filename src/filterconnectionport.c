#include <Windows.h>
#include <fltUser.h>
#include "include\filterconnectionport.h"
#include "include\utils.h"
#include "include\nt.h"

int open_nt_filterconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   HRESULT hRes = 0;
   PWSTR swzPortName = string_to_wide(swzNTPath);
   DWORD dwGrantedRights = 0;

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   hRes = FilterConnectCommunicationPort(swzPortName, 0, NULL, 0, NULL, phOut);
   if (hRes != S_OK)
   {
      res = hRes;
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
   if (swzPortName != NULL)
      safe_free(swzPortName);
   return res;
}