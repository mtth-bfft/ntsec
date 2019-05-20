#include <Windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <stdio.h>
#include <sddl.h>
#include <conio.h>
#include "include\main.h"
#include "include\directory.h"
#include "include\process.h"
#include "include\registry.h"
#include "include\token.h"
#include "include\nt.h"
#include "include\securitydescriptor.h"
#include "include\accessright.h"
#include "include\mitigations.h"
#include "include\file.h"
#include "include\process.h"
#include "include\service.h"
#include "include\rpc.h"
#include "include\alpc.h"
#include "include\utils.h"
#include "include\targets.h"

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
   _ftprintf(stderr, TEXT("      --nt         <nt_path>                   any NT object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --alpc       <nt_path>                   ALPC connection port, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --directory  <nt_path>                   object directory, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --event      <nt_path>                   event object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("   -f --file       <nt_path>|<win32_path>      file or directory object, by NT or Win32 path\n"));
   _ftprintf(stderr, TEXT("      --fltport    <nt_path>                   filter connection port object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --job        <nt_path>                   job object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --keyedevent <nt_path>                   keyed event object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --partition  <nt_path>                   memory partition object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --mutant     <nt_path>                   mutant object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("   -p --process    <pid>|<name>|current|caller process, by .exe name or id\n"));
   _ftprintf(stderr, TEXT("   -r --regkey     <nt_path>|<win32_path>      registry key, by NT or Win32 path\n"));
   _ftprintf(stderr, TEXT("      --section    <nt_path>                   section object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --semaphore  <nt_path>                   semaphore object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("   -s --service    <name>                      Windows service, by short name\n"));
   _ftprintf(stderr, TEXT("      --session    <nt_path>                   session object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("      --symlink    <nt_path>                   symbolic link object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("   -t --thread     <tid>|current               thread, by id or 'current'\n"));
   _ftprintf(stderr, TEXT("      --timer      <nt_path>                   timer object, by absolute NT path\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Generic operations for all types:\n"));
   _ftprintf(stderr, TEXT("      --sddl [new_sddl]         display (or replace) the security descriptor, as a SDDL string\n"));
   _ftprintf(stderr, TEXT("      --show-sd                 show the security descriptor as text\n"));
   _ftprintf(stderr, TEXT("      --explain-sd              show the security descriptor, describing each access right\n"));
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
   _ftprintf(stderr, TEXT("   -i --interactive             pop an interactive pseudo-shell\n"));
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
         if (_wcsicmp(swzCommand, L"exit") == 0 || _wcsicmp(swzCommand, L"quit") == 0)
            goto cleanup;
         fprintf(stderr, "\n");
         if (wcslen(swzCommand) > 0)
         {
            argv = CommandLineToArgvW(swzCommand, &argc);
            if (argv == NULL)
            {
               res = GetLastError();
               _ftprintf(stderr, TEXT(" [!] Error: CommandLineToArgvW() failed with code %u\n"), res);
               goto cleanup;
            }
            res = process_cmdline(argc, argv);
            if (res != 0)
               goto cleanup;
         }
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
   /************************ Target selection, one per type ************************/
   else if (_tcsicmp(TEXT("alpc"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'alpc' requires an absolute path to an ALPC port, or the name of a port in \\RPC Control\\\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_ALPC_CONNECTION_PORT;
   }
   else if (_tcsicmp(TEXT("directory"), argv[0]) == 0 || _tcsicmp(TEXT("dir"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'directory' requires an absolute path to a NT object directory\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_DIRECTORY_OBJECT;
   }
   else if (_tcsicmp(TEXT("event"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'event' requires an absolute path to a NT event object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_EVENT;
   }
   else if (_tcsicmp(TEXT("file"), argv[0]) == 0 || _tcsicmp(TEXT("f"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'file' requires an absolute NT path to a file or directory\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_FILE;
   }
   else if (_tcsicmp(TEXT("filterport"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'filterport' requires an absolute NT path to a NT filter connection port\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_FILTER_CONNECTION_PORT;
   }
   else if (_tcsicmp(TEXT("job"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'job' requires an absolute NT path to a NT job object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_JOB;
   }
   else if (_tcsicmp(TEXT("keyedevent"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'keyedevent' requires an absolute NT path to a NT keyed event object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_KEYED_EVENT;
   }
   else if (_tcsicmp(TEXT("memorypartition"), argv[0]) == 0 || _tcsicmp(TEXT("mempartition"), argv[0]) == 0 || _tcsicmp(TEXT("partition"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'memorypartition' requires an absolute NT path to a NT keyed event object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_MEMORY_PARTITION;
   }
   else if (_tcsicmp(TEXT("mutant"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'mutant' requires an absolute NT path to a NT mutant object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_MUTANT;
   }
   else if (_tcsicmp(TEXT("namedpipe"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'namedpipe' requires a named pipe name or an absolute NT path\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_FILE_NAMED_PIPE;
   }
   else if (_tcsicmp(TEXT("process"), argv[0]) == 0 || _tcsicmp(TEXT("p"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = 1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'process' requires a PID or image name\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_PROCESS;
   }
   else if (_tcsicmp(TEXT("regkey"), argv[0]) == 0 || _tcsicmp(TEXT("reg"), argv[0]) == 0 || _tcsicmp(TEXT("r"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'regkey' requires an absolute path to a NT registry key\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_REGKEY;
   }
   else if (_tcsicmp(TEXT("section"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'section' requires an absolute NT path to a NT section object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_SECTION;
   }
   else if (_tcsicmp(TEXT("semaphore"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'semaphore' requires an absolute NT path to a NT semaphore object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_SEMAPHORE;
   }
   else if (_tcsicmp(TEXT("service"), argv[0]) == 0 || _tcsicmp(TEXT("s"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'service' requires a service name\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_SERVICE;
   }
   else if (_tcsicmp(TEXT("session"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'session' requires an absolute NT path to a NT session object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_SESSION;
   }
   else if (_tcsicmp(TEXT("symboliclink"), argv[0]) == 0 || _tcsicmp(TEXT("symlink"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'symboliclink' requires an absolute NT path to a NT symbolic link object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_SYMBOLIC_LINK;
   }
   else if (_tcsicmp(TEXT("thread"), argv[0]) == 0 || _tcsicmp(TEXT("t"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'thread' requires a TID\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_THREAD;
   }
   else if (_tcsicmp(TEXT("timer"), argv[0]) == 0)
   {
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'timer' requires an absolute NT path to a NT timer object\n"));
         print_usage();
         goto cleanup;
      }
      swzTarget = argv[1];
      targetType = TARGET_TIMER;
   }
   else if (_tcsicmp(TEXT("nt"), argv[0]) == 0)
   {
      if (argc != 2 || argv[1][0] != TEXT('\\'))
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'nt' requires an absolute path to an NT object\n"));
         print_usage();
         goto cleanup;
      }
      res = get_nt_object_type(argv[1], &targetType);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Determining object type of '%s' failed with code %u\n"), argv[1], res);
         goto cleanup;
      }
      swzTarget = argv[1];
   }
   /************************ Generic commands that work on all types ************************/
   else if (_tcsicmp(TEXT("sddl"), argv[0]) == 0 || _tcsicmp(TEXT("show-sddl"), argv[0]) == 0)
   {
      if (argc == 1)
      {
         res = print_target_sddl(stdout, &targetType, swzTarget);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Error: printing target SDDL failed with code %u\n"), res);
            goto cleanup;
         }
      }
      else if (argc == 2)
      {
         _ftprintf(stderr, TEXT(" [!] Error: setting object SDDL is not supported yet\n"));
         res = ERROR_NOT_SUPPORTED;
         goto cleanup;
      }
      else
      {
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'sddl' takes at most one parameter\n"));
         res = ERROR_INVALID_PARAMETER;
         goto cleanup;
      }
   }
   else if (_tcsicmp(TEXT("sd"), argv[0]) == 0 || _tcsicmp(TEXT("show-sd"), argv[0]) == 0)
   {
      res = print_target_sd(stdout, &targetType, swzTarget);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: printing target security descriptor failed with code %u\n"), res);
         goto cleanup;
      }
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
   /************************ Process, thread and token specific commands ************************/
   else if (_tcsicmp(TEXT("open-token"), argv[0]) == 0)
   {
      if (targetType == TARGET_PROCESS)
      {
         targetType = TARGET_TOKEN_PRIMARY;
      }
      else if (targetType == TARGET_THREAD)
      {
         targetType = TARGET_TOKEN_IMPERSONATION;
      }
      else
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'open-token' only works on processes and threads\n"));
         print_usage();
         goto cleanup;
      }
   }
   else if (_tcsicmp(TEXT("show-token"), argv[0]) == 0)
   {
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'show-token' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY, &hToken);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: getting the target's token failed with code %u\n"), res);
         goto cleanup;
      }
      print_token(hToken);
   }
   else if (_tcsicmp(TEXT("enable-priv"), argv[0]) == 0 || _tcsicmp(TEXT("e"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'enable-priv' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }
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
      {
         _ftprintf(stderr, TEXT(" [!] Error: opening the target's token failed with code %u\n"), res);
         goto cleanup;
      }
      res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_ENABLED);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: enabling privilege %s in the target token failed with code %u\n"), swzPrivName, res);
         goto cleanup;
      }
      _ftprintf(stderr, TEXT(" [.] Privilege %s enabled\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("disable-priv"), argv[0]) == 0 || _tcsicmp(TEXT("d"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'disable-priv' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'disable-priv' requires a privilege name or wildcard\n"));
         print_usage();
         goto cleanup;
      }
      swzPrivName = argv[1];
      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: opening the target's token failed with code %u\n"), res);
         goto cleanup;
      }
      res = set_privilege(hToken, swzPrivName, 0);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: disabling privilege %s in the target token failed with code %u\n"), swzPrivName, res);
         goto cleanup;
      }
      _ftprintf(stderr, TEXT(" [.] Privilege %s disabled\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("remove-priv"), argv[0]) == 0)
   {
      PCTSTR swzPrivName = NULL;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'remove-priv' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }
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
      {
         _ftprintf(stderr, TEXT(" [!] Error: opening the target's token failed with code %u\n"), res);
         goto cleanup;
      }
      res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_REMOVED);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: removing privilege %s in the target token failed with code %u\n"), swzPrivName, res);
         goto cleanup;
      }
      _ftprintf(stderr, TEXT(" [.] Privilege %s removed\n"), swzPrivName);
   }
   else if (_tcsicmp(TEXT("impersonate"), argv[0]) == 0)
   {
      HANDLE hToken = INVALID_HANDLE_VALUE;

      if (targetType != TARGET_PROCESS && targetType != TARGET_THREAD &&
         targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'impersonate' only works on processes, threads, and tokens\n"));
         print_usage();
         goto cleanup;
      }

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
      if (res != 0)
         goto cleanup;
      res = set_impersonation_token(hToken);
      if (res != 0)
         goto cleanup;
      _ftprintf(stderr, TEXT(" [.] Impersonating token temporarily\n"));
   }
   else if (_tcsicmp(TEXT("execute"), argv[0]) == 0 || _tcsicmp(TEXT("x"), argv[0]) == 0)
   {
      HANDLE hNewProcess = INVALID_HANDLE_VALUE;
      HANDLE hToken = INVALID_HANDLE_VALUE;

      if (targetType == TARGET_PROCESS)
      {
         targetType = TARGET_TOKEN_PRIMARY;
      }
      else if (targetType == TARGET_THREAD)
      {
         targetType = TARGET_TOKEN_IMPERSONATION;
      }
      if (targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'execute' only works on primary (process) or impersonation (thread) access tokens\n"));
         print_usage();
         goto cleanup;
      }
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'execute' requires a command to execute\n"));
         print_usage();
         goto cleanup;
      }

      _ftprintf(stderr, TEXT(" [.] Executing command '%s'\n"), argv[1]);

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &hToken);
      if (res == 0)
      {
         res = create_process_with_token(hToken, (PTSTR)argv[1], &hNewProcess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Warning: process creation with duplicated token failed with code %u\n"), res);
            goto cleanup;
         }
      }
      else
      {
         _ftprintf(stderr, TEXT(" [!] Warning: opening target token for duplication failed with code %u\n"), res);
         if (targetType == TARGET_TOKEN_PRIMARY)
         {
            target_t procTargetType = TARGET_PROCESS;
            HANDLE hParentProcess = INVALID_HANDLE_VALUE;
            res = open_target_by_typeid(swzTarget, &procTargetType, PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS, &hParentProcess);
            if (res == 0)
            {
               res = create_reparented_process(hParentProcess, (PTSTR)argv[1], &hNewProcess);
               if (res == 0)
               {
                  _ftprintf(stderr, TEXT(" [.] Process %u created, reparented to %u to steal its primary token\n"),
                     GetProcessId(hNewProcess), GetProcessId(hParentProcess));
               }
               else
               {
                  _ftprintf(stderr, TEXT(" [!] Warning: creating process reparented to PID %u to steal its primary token failed with code %u\n"),
                     GetProcessId(hParentProcess), res);
               }
            }
            else if (res != ERROR_ACCESS_DENIED)
            {
               _ftprintf(stderr, TEXT(" [!] Warning: opening primary token failed with code %u\n"), res);
            }
         }
      }
   }
   /************************ Token specific commands ************************/
   else if (_tcsicmp(TEXT("assign"), argv[0]) == 0)
   {
      HANDLE hThread = INVALID_HANDLE_VALUE;
      HANDLE hToken = INVALID_HANDLE_VALUE;
      PCTSTR swzTargetThread = NULL;
      target_t assignedTargetType = TARGET_THREAD;

      if (targetType != TARGET_TOKEN_PRIMARY && targetType != TARGET_TOKEN_IMPERSONATION)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'assign' only works on tokens\n"));
         print_usage();
         goto cleanup;
      }
      if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: command 'assign' requires a thread ID\n"));
         print_usage();
         goto cleanup;
      }
      swzTargetThread = argv[1];

      res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken);
      if (res != 0)
         goto cleanup;
      res = open_target_by_typeid(swzTargetThread, &assignedTargetType, THREAD_SET_THREAD_TOKEN, &hThread);
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
   /************************ Process specific commands ************************/
   else if (_tcsicmp(TEXT("list-handles"), argv[0]) == 0)
   {
      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'list-handles' only works on processes\n"));
         print_usage();
         goto cleanup;
      }

      _ftprintf(stderr, TEXT(" [.] Handles held by process %s :\n"), swzTarget);
      //TODO
   }
   else if (_tcsicmp(TEXT("list-memmap"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'list-memmap' only works on processes\n"));
         print_usage();
         goto cleanup;
      }

      _ftprintf(stderr, TEXT(" [.] Memory map of process %s :\n"), swzTarget);

      res = open_target_by_typeid(swzTarget, &targetType, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: opening process %s to query its address space failed with code %u\n"),
            swzTarget, res);
         goto cleanup;
      }

      res = list_memmap(hProcess);

      CloseHandle(hProcess);
   }
   else if (_tcsicmp(TEXT("list-mitigations"), argv[0]) == 0 || _tcsicmp(TEXT("mitigations"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'list-mitigations' only works with a target process selected\n"));
         print_usage();
         goto cleanup;
      }
      res = open_target_by_typeid(swzTarget, &targetType, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
         goto cleanup;

      _ftprintf(stderr, TEXT(" [.] Mitigations enabled by process %s :\n"), swzTarget);
      res = list_process_mitigations(hProcess);
      CloseHandle(hProcess);
   }
   else if (_tcsicmp(TEXT("steal-token"), argv[0]) == 0)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      PTSTR swzTargetCommand = NULL;
      STARTUPINFOEX startInfo = { 0 };
      PROCESS_INFORMATION procInfo = { 0 };
      PPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
      SIZE_T dwAttrListSize = 0;
      ZeroMemory(&startInfo, sizeof(startInfo));
      ZeroMemory(&procInfo, sizeof(procInfo));
      startInfo.StartupInfo.cb = sizeof(startInfo);

      if (targetType != TARGET_PROCESS)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: command 'steal-token' only works with a target process selected\n"));
         print_usage();
         goto cleanup;
      }
      else if (argc != 2)
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: option 'steal-token' requires a command to execute\n"));
         print_usage();
         goto cleanup;
      }
      swzTargetCommand = (PTSTR)argv[1];

      res = open_target_by_typeid(swzTarget, &targetType, PROCESS_CREATE_PROCESS, &hProcess);
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
   /************************ Reachable objects enumeration commands ************************/
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
   else if (_tcsicmp(TEXT("proc-list"), argv[0]) == 0 || _tcsicmp(TEXT("process-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'process-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_processes_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("file-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      PCTSTR swzBaseNTPath = TEXT("\\");
      if (argc == 3)
         swzBaseNTPath = argv[2];
      if (argc >= 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'file-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_files_with(swzBaseNTPath, dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("reg-list"), argv[0]) == 0 || _tcsicmp(TEXT("regkey-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'regkey-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_keys_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("service-list"), argv[0]) == 0 || _tcsicmp(TEXT("svc-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'service-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_services_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("alpc-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'alpc-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_alpc_ports_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("namedpipe-list"), argv[0]) == 0)
   {
      PTSTR swzDesiredAccess = (PTSTR)argv[1];
      DWORD dwDesiredAccess = MAXIMUM_ALLOWED;
      if (argc == 2)
      {
         res = parse_access_right(swzDesiredAccess, &dwDesiredAccess);
         if (res != 0)
         {
            _ftprintf(stderr, TEXT(" [!] Invalid parameter: unable to parse 'namedpipe-list' argument as an access right\n"));
            print_usage();
            goto cleanup;
         }
      }
      res = enumerate_namedpipes_with(dwDesiredAccess);
      if (res != 0)
         goto cleanup;
   }
   else if (_tcsicmp(TEXT("rpc-list"), argv[0]) == 0 || _tcsicmp(TEXT("rpcs-list"), argv[0]) == 0 || _tcsicmp(TEXT("rpcs"), argv[0]) == 0)
   {
      if (targetType == TARGET_FILE)
      {
         res = list_rpc_named_pipe(swzTarget);
      }
      else if (targetType == TARGET_ALPC_CONNECTION_PORT)
      {
         res = list_rpc_alpc(swzTarget);
      }
      else
      {
         res = list_rpcs_mapped();
      }
   }
   /************************ Wrapper around other commands ************************/
   else if (_tcsicmp(TEXT("sandbox-check"), argv[0]) == 0)
   {
      _ftprintf(stderr, TEXT(" [!] Sandbox checklist: WIP\n"));
      res = ERROR_NOT_SUPPORTED;
   }
   else
   {
      res = -1;
      _ftprintf(stderr, TEXT(" [!] Invalid parameter: unknown command '%s'\n"), argv[0]);
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
   set_privilege_caller(SE_ASSIGNPRIMARYTOKEN_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_INCREASE_QUOTA_NAME, SE_PRIVILEGE_ENABLED);
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
         _ftprintf(stderr, TEXT(" [!] Invalid parameter: unexpected argument '%s'\n"), argv[argn]);
         print_usage();
         goto cleanup;
      }
   }

cleanup:
   if (verbosity > 0)
      _tprintf(TEXT(" [.] Exiting with code %d\n"), res);
   return res;
}