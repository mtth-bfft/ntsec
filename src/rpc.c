#include <Windows.h>
#include <tchar.h>
#include <rpc.h>
#include <stdio.h>
#include "include\rpc.h"
#include "include\token.h"

static int print_interface_id(RPC_IF_ID *pIfID)
{
   int res = 0;
   RPC_STATUS status = 0;
   RPC_WSTR uuidStr = NULL;

   status = UuidToString(&(pIfID->Uuid), &uuidStr);
   if (status != RPC_S_OK)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: UuidToString() failed with code %u\n"), status);
      goto cleanup;
   }
   _tprintf(TEXT("%s (%u.%u)"), uuidStr, pIfID->VersMajor, pIfID->VersMinor);

cleanup:
   RpcStringFree(&uuidStr);
   return res;
}

int list_rpcs_mapped()
{
   int res = 0;
   BOOL bImpersonating = FALSE;
   RPC_STATUS status = 0;
   RPC_EP_INQ_HANDLE inqHandle = NULL;
   RPC_IF_ID ifID = { 0 };
   RPC_BINDING_HANDLE bindingHandle = NULL;
   RPC_WSTR stringBinding = NULL;

   res = start_impersonated_operation();
   if (res != 0)
      goto cleanup;
   bImpersonating = TRUE;
   
   _tprintf(TEXT(" [.] Reachable RPC endpoints from endpoint mapper:\n"));

   status = RpcMgmtEpEltInqBegin(NULL, RPC_C_EP_ALL_ELTS, NULL, RPC_C_VERS_ALL, NULL, &inqHandle);
   if (status != RPC_S_OK)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: RpcMgmtEpEltInqBegin() failed with code %u\n"), status);
      goto cleanup;
   }

   while ((status = RpcMgmtEpEltInqNext(inqHandle, &ifID, &bindingHandle, NULL, NULL)) == RPC_S_OK)
   {
      status = RpcBindingToStringBinding(bindingHandle, &stringBinding);
      RpcBindingFree(bindingHandle);
      if (status != RPC_S_OK)
      {
         res = status;
         _ftprintf(stderr, TEXT(" [!] Error: RpcBindingToStringBinding() failed with code %u\n"), status);
         continue;
      }
      print_interface_id(&ifID);
      _tprintf(TEXT(" %s\n"), stringBinding);
      RpcStringFree(&stringBinding);
   }
   if (status != RPC_X_NO_MORE_ENTRIES)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Error: RpcMgmtEpEltInqNext() failed with code %u\n"), status);
      goto cleanup;
   }

cleanup:
   if (bImpersonating)
   {
      int res2 = end_impersonated_operation();
      if (res == 0 && res2 != 0)
         res = res2;
   }
   if (inqHandle != NULL)
      RpcMgmtEpEltInqDone(&inqHandle);
   return res;
}

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

   _tprintf(TEXT(" [.] Reachable RPC interfaces:\n"));

   for (ULONG i = 0; i < pIntfIDs->Count; i++)
   {
      print_interface_id(pIntfIDs->IfId[i]);
      _tprintf(TEXT("\n"));
   }

cleanup:
   if (pIntfIDs != NULL)
      RpcIfIdVectorFree(&pIntfIDs);
   if (stringBinding != NULL)
      RpcStringFree(&stringBinding);
   return res;
}

int list_rpc_alpc(PCTSTR swzALPCPortNTPath)
{
   int res = 0;
   RPC_STATUS status = 0;
   RPC_WSTR stringBinding = NULL;
   RPC_BINDING_HANDLE bindingHandle = NULL;
   RPC_IF_ID_VECTOR *pIntfIDs = NULL;

   status = RpcStringBindingCompose(
      NULL, // no specific object UUID
      TEXT("ncalrpc"), // transport is through named pipe
      NULL, // on local host
      (PTSTR)swzALPCPortNTPath, // absolute NT path to ALPC connection port
      NULL, // options (ALPC-specific)
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

   _tprintf(TEXT(" [.] Reachable RPC interfaces:\n"));

   for (ULONG i = 0; i < pIntfIDs->Count; i++)
   {
      print_interface_id(pIntfIDs->IfId[i]);
      _tprintf(TEXT("\n"));
   }

cleanup:
   if (pIntfIDs != NULL)
      RpcIfIdVectorFree(&pIntfIDs);
   if (stringBinding != NULL)
      RpcStringFree(&stringBinding);
   return res;
}