#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\mitigations.h"

int list_process_mitigations(HANDLE hProcess)
{
   int res = 0;
   PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 };
   PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 };
   PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynCodePolicy = { 0 };
   PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handleCheckPolicy = { 0 };
   PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = { 0 };
   PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPointPolicy = { 0 };
   PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 };
   PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
   PROCESS_MITIGATION_FONT_DISABLE_POLICY fontPolicy = { 0 };
   PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 };
   PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sideChannelPolicy = { 0 };

   if (!GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying DEP policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying ASLR policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &dynCodePolicy, sizeof(dynCodePolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying dynamic code policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessStrictHandleCheckPolicy, &handleCheckPolicy, sizeof(handleCheckPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying handle check policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessSystemCallDisablePolicy, &syscallPolicy, sizeof(syscallPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying syscall filtering policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessExtensionPointDisablePolicy, &extPointPolicy, sizeof(extPointPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying extension point policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying CFG policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying signature policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessFontDisablePolicy, &fontPolicy, sizeof(fontPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying font loading policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying image loading policy on process failed with code %u\n"), res);
   }
   if (!GetProcessMitigationPolicy(hProcess, ProcessSideChannelIsolationPolicy, &sideChannelPolicy, sizeof(sideChannelPolicy)))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: querying side channel isolation policy on process failed with code %u\n"), res);
   }

   if (!depPolicy.Enable)
   {
      printf(" [x] DEP is not enabled\n");
   }
   else
   {
      if (!depPolicy.Permanent)
         printf(" [x] DEP is not locked down, can be disabled\n");
      else
         printf(" [.] DEP is enabled and locked down\n");
      if (!depPolicy.DisableAtlThunkEmulation)
         printf(" [x] DEP is enabled but allows legacy ATL-compatible execution\n");
   }

   if (aslrPolicy.EnableForceRelocateImages && aslrPolicy.EnableBottomUpRandomization && aslrPolicy.EnableHighEntropy && aslrPolicy.DisallowStrippedImages)
      printf(" [.] ASLR is enforced for all images and allocation types, with high entropy settings\n");
   if (!aslrPolicy.EnableForceRelocateImages)
      printf(" [x] ASLR is not enforced for images that don't opt-in to ASLR with /DYNAMICBASE\n");
   if (!aslrPolicy.EnableBottomUpRandomization)
      printf(" [x] ASLR is not enforced for dynamic allocations (bottom-up nor top-down) made by code compiled without /DYNAMICBASE\n");
   if (!aslrPolicy.EnableHighEntropy)
      printf(" [x] ASLR use of >32 bits is not enforced for 64-bit applications compiled without /HIGHENTROPYVA\n");
   if (!aslrPolicy.DisallowStrippedImages)
      printf(" [x] ASLR is not enforced for images with stripped relocation tables\n");

   if (!dynCodePolicy.ProhibitDynamicCode)
   {
      printf(" [x] Dynamic code modification is not blocked\n");
   }
   else
   {
      if (!dynCodePolicy.AllowThreadOptOut && !dynCodePolicy.AllowRemoteDowngrade)
         printf(" [.] Non-image-backed code and code modification are blocked permanently\n");
      if (dynCodePolicy.AllowThreadOptOut)
         printf(" [x] Dynamic code modification is not locked down, threads can SetThreadInformation(ThreadDynamicCodePolicy, THREAD_DYNAMIC_CODE_ALLOW)\n");
      if (dynCodePolicy.AllowRemoteDowngrade)
         printf(" [x] Dynamic code modification can be re-allowed by external non-AppContainer processes\n");
   }

   if (!handleCheckPolicy.RaiseExceptionOnInvalidHandleReference)
      printf(" [x] Invalid handle references do not kill the offending process, handle bruteforce possible\n");
   else if (!handleCheckPolicy.HandleExceptionsPermanentlyEnabled)
      printf(" [x] Handle bruteforce protection can be disabled on-demand\n");
   else
      printf(" [.] Handle bruteforce is set up permanently to kill any offending process\n");

   if (syscallPolicy.DisallowWin32kSystemCalls)
      printf(" [.] win32k graphics system calls are blocked\n");
   else
      printf(" [x] win32k graphics system calls are allowed\n");

   if (extPointPolicy.DisableExtensionPoints)
      printf(" [.] Third-party extension points (AppInit DLLs, Winsock Layered Service Providers, Global Windows Hooks, Globoal Windows Hooks) are not applied\n");
   else
      printf(" [x] Third-party extension points (AppInit DLLs, Winsock Layered Service Providers, Global Windows Hooks, Globoal Windows Hooks) are applied\n");

   if (!cfgPolicy.EnableControlFlowGuard)
   {
      printf(" [x] Control Flow Guard is not enabled\n");
   }
   else
   {
      if (cfgPolicy.StrictMode && cfgPolicy.EnableExportSuppression)
         printf(" [.] CFG is enforced and blocks all possible calls\n");
      if (!cfgPolicy.StrictMode)
         printf(" [x] CFG-incompatible DLLs are allowed to load\n");
      if (!cfgPolicy.EnableExportSuppression)
         printf(" [x] CFG doesn't block indirect calls to functions not resolved with GetProcAddress()\n");
   }

   if (!signaturePolicy.MitigationOptIn)
      printf(" [.] Image loading is not restricted by signature\n");
   else if (signaturePolicy.MicrosoftSignedOnly && signaturePolicy.StoreSignedOnly)
      printf(" [.] Image loading is restricted to Microsoft Store and Microsoft signed binaries\n");
   else if (signaturePolicy.MicrosoftSignedOnly)
      printf(" [.] Image loading is restricted to Microsoft signed binaries\n");
   else if (signaturePolicy.StoreSignedOnly)
      printf(" [.] Image loading is restricted to Microsoft Store signed binaries\n");

   if (fontPolicy.DisableNonSystemFonts)
      printf(" [.] Non-system font loading is blocked\n");
   else
      printf(" [x] Can load arbitrary font files\n");

   if (imageLoadPolicy.NoRemoteImages)
      printf(" [.] Cannot load executables from remote file shares\n");
   else
      printf(" [x] Can load additional executables from remote file shares\n");
   if (imageLoadPolicy.NoLowMandatoryLabelImages)
      printf(" [.] Cannot load executables with a low mandatory integrity level\n");
   else
      printf(" [x] Can load additional executables with a low mandatory integrity level\n");
   if (imageLoadPolicy.PreferSystem32Images)
      printf(" [.] DLL search order overriden, System32 is searched first to prevent DLL planting\n");
   else
      printf(" [x] Standard DLL search order is used, doesn't block DLL planting\n");

   return res;
}