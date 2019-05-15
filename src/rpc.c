#include <Windows.h>
#include <tchar.h>
#include <rpc.h>
#include <stdio.h>
#include "include\rpc.h"

int list_rpc_named_pipe(PCTSTR swzNamedPipe)
{
   int res = 0;
   RPC_STATUS status = 0;
   RPC_WSTR stringBinding = NULL;
   RPC_BINDING_HANDLE bindingHandle = NULL;
   RPC_IF_ID_VECTOR *pIntfIDs = NULL;
   TCHAR swzPipeFormattedName[MAX_PATH] = { 0 };

   if (_tcsnicmp(TEXT("\\Device\\NamedPipe\\"), swzNamedPipe, 18) == 0)
      swzNamedPipe += 18;
   _sntprintf_s(swzPipeFormattedName, MAX_PATH, MAX_PATH, TEXT("\\pipe\\%s"), swzNamedPipe);
   
   status = RpcStringBindingCompose(
      NULL, // no specific object UUID
      TEXT("ncacn_np"), // transport is through named pipe
      NULL, // on local host
      swzPipeFormattedName, // pipe name
      NULL, // options (named-pipe-specific)
      &stringBinding
   );
   if (status != RPC_S_OK)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: RpcStringBindingCompose() failed with code %u\n"), status);
      goto cleanup;
   }
   
   _tprintf(TEXT(" [.] RPC binding string: %s\n"), stringBinding);

   status = RpcBindingFromStringBinding(stringBinding, &bindingHandle);
   if (status != RPC_S_OK)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: RpcBindingFromStringBinding() failed with code %u\n"), status);
      goto cleanup;
   }

   _tprintf(TEXT(" [.] RPC binding established\n"));

   status = RpcMgmtInqIfIds(bindingHandle, &pIntfIDs);
   if (status != RPC_S_OK)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: RpcMgmtInqIfIds() failed with code %u\n"), status);
      goto cleanup;
   }

   _tprintf(TEXT(" [.] RPC interfaces exposed:\n"));

   for (ULONG i = 0; i < pIntfIDs->Count; i++)
   {
      RPC_WSTR uuidStr = NULL;
      status = UuidToString(&(pIntfIDs->IfId[i]->Uuid), &uuidStr);
      if(status != RPC_S_OK)
      {
         _ftprintf(stderr, TEXT(" [!] Error: UuidToString() failed with code %u\n"), status);
         continue;
      }
      _tprintf(TEXT(" %s (%u.%u)\n"), uuidStr, pIntfIDs->IfId[i]->VersMajor, pIntfIDs->IfId[i]->VersMinor);
      RpcStringFree(&uuidStr);
   }

cleanup:
   if (pIntfIDs != NULL)
      RpcIfIdVectorFree(&pIntfIDs);
   if (stringBinding != NULL)
      RpcStringFree(&stringBinding);
   return res;
}