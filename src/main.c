#include <Windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <stdio.h>
#include <sddl.h>
#include <conio.h>
#include "main.h"
#include "process.h"
#include "registry.h"
#include "token.h"
#include "nt.h"
#include "securitydescriptor.h"
#include "accessright.h"
#include "mitigations.h"
#include "files.h"
#include "process.h"
#include "services.h"
#include "utils.h"

#define MAX_COMMAND_LEN 1000
#define MAX_NT_PATH_LEN 1000

int verbosity = 0;
BOOL bAlwaysYes = FALSE;
BOOL bAlwaysNo = FALSE;
target_t targetType = TARGET_PROCESS;
PCTSTR swzTarget = TEXT("caller");

static void print_version()
{
   _ftprintf(stderr, TEXT("ntsec v1.0 - https://github.com/mtth-bfft/ntsec \n"));
}

static void print_usage()
{
   _ftprintf(stderr, TEXT("ntsec.exe [options] <operations>\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations are processed *from left to right*. By default, the calling process is selected.\n"));
   _ftprintf(stderr, TEXT("Some operations might fail because you lack some privileges, in which case you will be prompted\n"));
   _ftprintf(stderr, TEXT("to confirm an elevation operation, if one is deemed possible. To avoid hanging indefinitely in\n"));
   _ftprintf(stderr, TEXT("case user interaction is impossible, use `-n`.\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Supported object types: process, thread, token, file, directory, namedpipe, pipe, filemap,\n"));
   _ftprintf(stderr, TEXT("                        service, regkey, job, event, mutex, semaphore, timer, mempartition\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Select a securable object:\n"));
   _ftprintf(stderr, TEXT("   -p --process <pid>|<name>|current|caller   select the given process by .exe name or id\n"));
   _ftprintf(stderr, TEXT("   -t --thread  <tid>|current                 select the given thread by id\n"));
   _ftprintf(stderr, TEXT("   -r --regkey  <nt_path>|<win32_path>        select the given registry key by NT or Win32 path\n"));
   _ftprintf(stderr, TEXT("   -f --file    <nt_path>|<win32_path>        select the given file object by NT or Win32 path\n"));
   _ftprintf(stderr, TEXT("   -o --ntobj   <nt_path>                     select the given NT object (device, alpc port, etc.)\n"));
   _ftprintf(stderr, TEXT("   -s --service <name>                        select the given service by short name\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Generic operations for all types:\n"));
   _ftprintf(stderr, TEXT("   --sddl [new_sddl]            display (or replace) the security descriptor, as a SDDL string\n"));
   _ftprintf(stderr, TEXT("   --show-sd                    show the security descriptor as text\n"));
   _ftprintf(stderr, TEXT("   --explain-sd                 show the security descriptor, describing each access right\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on processes:\n"));
   _ftprintf(stderr, TEXT("   --open-token                 select the process' primary token\n"));
   _ftprintf(stderr, TEXT("   --list-mitigations           display status of each process mitigation policy\n"));
   _ftprintf(stderr, TEXT("   --list-handles               list all open handles, their target and permissions\n"));
   _ftprintf(stderr, TEXT("   --list-memmap                list all memory mappings and their permissions\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on threads:\n"));
   _ftprintf(stderr, TEXT("   --open-token                 select the thread' impersonation token, if any\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on access tokens:\n"));
   _ftprintf(stderr, TEXT("   --list-sids                  lists all SIDs held and their attributes\n"));
   _ftprintf(stderr, TEXT("   --list-privs                 lists all privileges held and their status\n"));
   _ftprintf(stderr, TEXT("   --show-token                 display user, groups, integrity, privileges, etc.\n"));
   _ftprintf(stderr, TEXT("   -e --enable-priv  <name>     enable a disabled privilege (use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   -d --disable-priv <name>     disable an enabled privilege (use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   --remove-priv     <name>     remove a privilege entirely (cannot be undone, use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   --assign <tid>               set the given thread's impersonation token to be the selected token\n"));
   _ftprintf(stderr, TEXT("   --impersonate                impersonate the selected token for operations that follow\n"));
   _ftprintf(stderr, TEXT("                                (requires SeImpersonatePrivilege)\n"));
   _ftprintf(stderr, TEXT("   --stop-impersonating         stop impersonating for operations that follow\n"));
   _ftprintf(stderr, TEXT("   -x --execute <cmd>           create a process holding a copy of the selected token (requires an opened\n"));
   _ftprintf(stderr, TEXT("                                process with PROCESS_CREATE_PROCESS rights, or SeAssignPrimaryTokenPrivilege)\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Enumerate accessible objects (optionally on which we have a specific access right, or another criteria)\n"));
   _ftprintf(stderr, TEXT("Takes privileges/open handles into account. Doesn't select objects, use while impersonating a token:\n"));
   _ftprintf(stderr, TEXT("   --processes-with [access_right]|[sid]|[privilege]\n"));
   _ftprintf(stderr, TEXT("   --threads-with   [access_right]|[sid]|[privilege]\n"));
   _ftprintf(stderr, TEXT("   --regkeys-with   [access_right]\n"));
   _ftprintf(stderr, TEXT("   --files-with     [access_right]\n"));
   _ftprintf(stderr, TEXT("   --ntobjs-with    [access_right]\n"));
   _ftprintf(stderr, TEXT("   --services-with  [access_right]\n"));
   _ftprintf(stderr, TEXT("   --anything-with  [access_right]\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Convenience function to explain security descriptors:\n"));
   _ftprintf(stderr, TEXT("   --explain-sd  [type:]<sddl>  describe as text the given SDDL string, optionally with an object type\n"));
   _ftprintf(stderr, TEXT("   --resolve-sid <sid>|<name>   resolve a name to a SID, and vice versa\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Options:\n"));
   _ftprintf(stderr, TEXT("   -i --interactive             drop to an interactive pseudo-shell\n"));
   _ftprintf(stderr, TEXT("   -y --yes                     don't prompt for consent, assume yes\n"));
   _ftprintf(stderr, TEXT("   -n --no                      don't prompt for consent, assume no\n"));
   _ftprintf(stderr, TEXT("   -v --verbose                 increase verbosity (can be repeated)\n"));
   _ftprintf(stderr, TEXT("   -h --help                    display this help text\n"));
   _ftprintf(stderr, TEXT("   -V --version                 display the current version\n"));
   _ftprintf(stderr, TEXT("\n"));
}

int run_interactive_loop()
{
   int res = 0;
   DWORD dwCmdLen = 0;
   PTSTR swzCwd = safe_alloc((MAX_NT_PATH_LEN + 1) * sizeof(TCHAR));
   PWSTR swzCommand = safe_alloc(MAX_COMMAND_LEN + 1);

   _tcscpy_s(swzCwd, MAX_NT_PATH_LEN + 1, TEXT("\\"));

   fprintf(stderr, "NT> ");
   fflush(stderr);

   while (1)
   {
      wint_t c = _getwch();
      if (c == L'\x03') // Ctrl-C
      {
         printf("\nNT> exit\n");
         break;
      }
      else if (c == L'\b') // Backspace
      {
         if (dwCmdLen > 0)
         {
            fprintf(stderr, "\x08 \x08");
            fflush(stderr);
            swzCommand[--dwCmdLen] = L'\x00';
         }
      }
      else if (c == L'\x0D') // Enter
      {
         int argc = 0;
         PWSTR *argv = NULL;

         swzCommand[dwCmdLen] = L'\x00';
         argv = CommandLineToArgvW(swzCommand, &argc);
         if (argv == NULL)
         {
            res = GetLastError();
            _ftprintf(stderr, TEXT(" [!] Error: CommandLineToArgvW() failed with code %u\n"), res);
            goto cleanup;
         }

         fprintf(stderr, "\n");
         if (_wcsicmp(swzCommand, L"exit") == 0 || _wcsicmp(swzCommand, L"quit") == 0)
            goto cleanup;
         res = process_cmdline(argc, argv);
         if (res != 0)
            goto cleanup;
         dwCmdLen = 0;
         fprintf(stderr, "NT> ");
         fflush(stderr);
      }
      else if (c == L'\t')
      {
         // TODO: tab-completion
      }
      else
      {
         swzCommand[dwCmdLen++] = c;
         fprintf(stderr, "%C", c);
         fflush(stderr);
         if (dwCmdLen == MAX_COMMAND_LEN)
         {
            fprintf(stderr, "\nError: command too long\n");
            dwCmdLen = 0;
         }
      }
   }

cleanup:
   if (swzCommand != NULL)
      safe_free(swzCommand);
   if (swzCwd != NULL)
      safe_free(swzCwd);
   return res;
}

int process_cmdline(int argc, PCWSTR argv[])
{
   int res = 0;

   if (_wcsnicmp(argv[0], L"--", 2) == 0)
      argv[0] += 2;
   else if (_wcsnicmp(argv[0], L"-", 1) == 0)
      argv[0]++;

   if (_wcsicmp(argv[0], L"interactive") == 0 || _wcsicmp(argv[0], L"i") == 0)
   {
      res = run_interactive_loop();
   }
   else if (_tcsicmp(TEXT("help"), argv[0]) == 0 || _tcsicmp(TEXT("h"), argv[0]) == 0 || _tcsicmp(TEXT("?"), argv[0]) == 0)
   {
      print_usage();
   }
   else if (_tcsicmp(TEXT("version"), argv[0]) == 0 || _tcscmp(TEXT("V"), argv[0]) == 0)
   {
      print_version();
   }
   else if (_tcsicmp(TEXT("verbose"), argv[0]) == 0 || _tcscmp(TEXT("v"), argv[0]) == 0)
   {
      verbosity++;
   }
   else if (_tcscmp(TEXT("no"), argv[0]) == 0 || _tcsicmp(TEXT("n"), argv[0]) == 0)
   {
      bAlwaysNo = TRUE;
      bAlwaysYes = FALSE;
   }
   else if (_tcscmp(TEXT("yes"), argv[0]) == 0 || _tcsicmp(TEXT("y"), argv[0]) == 0)
   {
      bAlwaysYes = TRUE;
      bAlwaysNo = FALSE;
   }
   else if (_tcsicmp(TEXT("process"), argv[0]) == 0 || _tcsicmp(TEXT("p"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'process' requires a PID or image name\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_PROCESS;
   }
   else if (_tcsicmp(TEXT("thread"), argv[0]) == 0 || _tcsicmp(TEXT("t"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'thread' requires a TID\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_THREAD;
   }
   else if (_tcsicmp(TEXT("regkey"), argv[0]) == 0 || _tcsicmp(TEXT("r"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'regkey' requires an absolute path\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_REGKEY;
   }
   else if (_tcsicmp(TEXT("file"), argv[0]) == 0 || _tcsicmp(TEXT("f"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'file' requires a Win32 or NT path\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_FILE;
   }
   else if (_tcsicmp(TEXT("ntobj"), argv[0]) == 0 || _tcsicmp(TEXT("o"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'ntobj' requires an absolute NT path\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_NT_OBJECT;
   }
   else if (_tcsicmp(TEXT("show-sddl"), argv[0]) == 0)
   {
      res = print_target_sd(targetType, swzTarget, FALSE);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("show-sd"), argv[0]) == 0)
   {
      res = print_target_sd(targetType, swzTarget, TRUE);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("show-token"), argv[0]) == 0)
   {
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_PRIMARY_TOKEN && targetType != TARGET_IMPERSONATION_TOKEN)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'show-token' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY, &hToken);
      if (res != 0)
         goto cleanup;
      print_token(hToken);
   }
   else if (_tcsicmp(TEXT("open-token"), argv[0]) == 0)
   {
      if (targetType == TARGET_PROCESS)
      {
         targetType = TARGET_PRIMARY_TOKEN;
      }
      else if (targetType == TARGET_THREAD)
      {
         targetType = TARGET_IMPERSONATION_TOKEN;
      }
      else
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'open-token' only works on processes and threads\n"));
         print_usage();
         goto cleanup;
      }
   }
   else if (_tcsicmp(TEXT("enable-priv"), argv[0]) == 0 || _tcsicmp(TEXT("e"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'enable-priv' requires a privilege name or wildcard\n"));
         print_usage();
         goto cleanup;
      }
      swzPrivName = argv[1];
      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
      if (res != 0)
         goto cleanup;
      res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_ENABLED);
      if (res != 0)
         goto cleanup;
      _ftprintf(stderr, TEXT(" [.] Privilege %s enabled\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("disable-priv"), argv[0]) == 0 || _tcsicmp(TEXT("-d"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'disable-priv' requires a privilege name or wildcard\n"));
         print_usage();
         goto cleanup;
      }
      swzPrivName = argv[1];
      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
      if (res != 0)
         goto cleanup;
      res = set_privilege(hToken, swzPrivName, 0);
      if (res != 0)
         goto cleanup;
      _ftprintf(stderr, TEXT(" [.] Privilege %s disabled\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("remove-priv"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'remove-priv' requires a privilege name or wildcard\n"));
         print_usage();
         goto cleanup;
      }
      swzPrivName = argv[1];
      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
      if (res != 0)
         goto cleanup;
      res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_REMOVED);
      if (res != 0)
         goto cleanup;
      _ftprintf(stderr, TEXT(" [.] Privilege %s removed\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("assign"), argv[0]) == 0)
   {
      HANDLE hThread = INVALID_HANDLE_VALUE;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      PCTSTR swzTargetThread = NULL;

      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'assign' requires a privilege name or wildcard\n"));
         print_usage();
         goto cleanup;
      }
      swzTargetThread = argv[1];

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken);
      if (res != 0)
         goto cleanup;
      res = open_target(swzTargetThread, TARGET_THREAD, THREAD_SET_THREAD_TOKEN, &hThread);
      if (res != 0)
         goto cleanup;
      if (!SetThreadToken(&hThread, hToken))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: setting thread token failed with code %u\n"), res);
         goto cleanup;
      }
      _ftprintf(stderr, TEXT(" [.] Token assigned to thread %s\n"), swzTargetThread);
   }
   else if (_tcsicmp(TEXT("impersonate"), argv[0]) == 0)
   {
      HANDLE hToken = INVALID_HANDLE_VALUE;
      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
      if (res != 0)
         goto cleanup;
      res = set_impersonation_token(hToken);
      if (res != 0)
         goto cleanup;
      _ftprintf(stderr, TEXT(" [.] Impersonating token temporarily\n"));
   }
   else if (_tcsicmp(TEXT("stop-impersonating"), argv[0]) == 0)
   {
      if (!RevertToSelf())
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: reverting impersonation failed with code %u\n"), res);
         goto cleanup;
      }
      _ftprintf(stderr, TEXT(" [.] Stopped impersonating token\n"));
   }
   else if (_tcsicmp(TEXT("list-handles"), argv[0]) == 0)
   {
      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'list-handles' only works on processes\n"));
         print_usage();
         goto cleanup;
      }

      _ftprintf(stderr, TEXT(" [.] Handles held by process %s :\n"), swzTarget);
      //TODO
   }
   else if (_tcsicmp(TEXT("steal-token"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      PTSTR swzTargetCommand = NULL;
      STARTUPINFOEX startInfo = { 0 };
      PROCESS_INFORMATION procInfo = { 0 };
      PPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
      DWORD dwAttrListSize = 0;
      ZeroMemory(&startInfo, sizeof(startInfo));
      ZeroMemory(&procInfo, sizeof(procInfo));
      startInfo.StartupInfo.cb = sizeof(startInfo);

      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'steal-token' only works with a target process selected\n"));
         print_usage();
         goto cleanup;
      }
      else if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: option 'steal-token' requires a command to execute\n"));
         print_usage();
         goto cleanup;
      }
      swzTargetCommand = (PTSTR)argv[1];

      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_CREATE_PROCESS, &hProcess);
      if (res != 0)
         goto cleanup;

      InitializeProcThreadAttributeList(NULL, 1, 0, &dwAttrListSize);
      pAttrList = safe_alloc(dwAttrListSize);
      startInfo.lpAttributeList = pAttrList;
      if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &dwAttrListSize))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: InitializeProcThreadAttributeList() failed with code %u\n"), res);
         goto cleanup;
      }
      if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(PHANDLE), NULL, NULL))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) failed with code %u\n"), res);
         goto cleanup;
      }
      if (!CreateProcess(NULL, swzTargetCommand, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP | EXTENDED_STARTUPINFO_PRESENT,
         NULL, NULL, (LPSTARTUPINFO)&startInfo, &procInfo))
      {
         res = GetLastError();
         DeleteProcThreadAttributeList(pAttrList);
         safe_free(pAttrList);
         _ftprintf(stderr, TEXT(" [!] Error: child process creation failed with code %u\n"), res);
         goto cleanup;
      }
      DeleteProcThreadAttributeList(pAttrList);
      safe_free(pAttrList);
      CloseHandle(hProcess);
      _ftprintf(stderr, TEXT(" [.] Token stolen by child process %u executing %s\n"), procInfo.dwProcessId, swzTargetCommand);
   }
   else if (_tcsicmp(TEXT("list-mitigations"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;

      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'list-mitigations' only works with a target process selected\n"));
         print_usage();
         goto cleanup;
      }

      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
         goto cleanup;

      _ftprintf(stderr, TEXT(" [.] Mitigations enabled by process %s :\n"), swzTarget);
      res = list_process_mitigations(hProcess);
      CloseHandle(hProcess);
   }
   else if (_tcsicmp(TEXT("find-ntobj"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: unable to parse 'find-ntobj' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_nt_objects_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("find-proc"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: unable to parse 'find-proc' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_processes_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("find-file"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: unable to parse 'find-file' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_files_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("find-regkey"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: unable to parse 'find-regkey' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_keys_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("find-service"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: unable to parse 'find-service' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_services_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("sandbox-check"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;

      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'sandbox-check' only works with a target process selected\n"));
         print_usage();
         goto cleanup;
      }

      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
         goto cleanup;

      _ftprintf(stderr, TEXT(" [.] Mitigations enabled by process %s :\n"), swzTarget);
      res = list_process_mitigations(hProcess);
      CloseHandle(hProcess);
   }
   else
   {
      res = -1;
      _ftprintf(stderr, TEXT(" [!] Error: unknown command '%s'\n"), argv[0]);
      print_usage();
      goto cleanup;
   }

cleanup:
   return res;
}

int wmain(int argc, PCWSTR argv[])
{
   int res = 0;

   resolve_imports();

   if (argc < 2)
   {
      res = 1;
      print_usage();
      goto cleanup;
   }

   // Privileges that will be useful anyway if we try to access files, processes, threads, their token, or their security descriptor's SACL
   set_privilege_caller(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_SECURITY_NAME, SE_PRIVILEGE_ENABLED);

   for (int argn = 1; argn < argc; argn++)
   {
      if (_wcsnicmp(argv[argn], L"-", 1) == 0)
      {
         PCWSTR *cmd_argv = &(argv[argn++]);
         int cmd_argc = 1;
         while (argn < argc && _wcsnicmp(argv[argn], L"-", 1) != 0)
         {
            cmd_argc++;
            argn++;
         }
         argn--;
         res = process_cmdline(cmd_argc, cmd_argv);
         if (res != 0)
            goto cleanup;
      }
      else
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Error: invalid argument '%s'\n"), argv[argn]);
         print_usage();
         goto cleanup;
      }
   }

cleanup:
   if (verbosity > 0)
      _tprintf(TEXT(" [.] Exiting with code %d\n"), res);
   return res;
}