#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <sddl.h>
#include "process.h"
#include "registry.h"
#include "token.h"
#include "nt.h"
#include "utils.h"

int verbosity = 0;

static void print_version()
{
   _ftprintf(stderr, TEXT("ntsec v1.0 - https://github.com/mtth-bfft/ntsec \n\n"));
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
   _ftprintf(stderr, TEXT("Select a securable object:\n"));
   _ftprintf(stderr, TEXT("   -p --process <pid>|<name>|caller    select the given process by .exe name or id\n"));
   _ftprintf(stderr, TEXT("   -t --thread  <tid>|current          select the given thread by id, or ntsec's main and only thread\n"));
   _ftprintf(stderr, TEXT("   -r --regkey  <key>                  select the given registry key by name\n"));
   _ftprintf(stderr, TEXT("   -f --file    <path>                 select the given file or directory by NT or Win32 path\n"));
   _ftprintf(stderr, TEXT("   -k --kernobj <nt_path>              select the given kernel object (mutex, semaphore, event, job, etc.) by NT path\n"));
   _ftprintf(stderr, TEXT("   -s --service <name>                 select the given service by name\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Generic operations for all types:\n"));
   _ftprintf(stderr, TEXT("   --show-sd                     describe security descriptor of the selected object\n"));
   _ftprintf(stderr, TEXT("   --show-sddl                   display SD of the selected object as a string\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on processes:\n"));
   _ftprintf(stderr, TEXT("   --open-token                  select the process' primary token\n"));
   _ftprintf(stderr, TEXT("   --steal-token <cmd>           steal the process' primary token by executing the given command as a reparented process\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on threads:\n"));
   _ftprintf(stderr, TEXT("   --open-token                  select the thread' impersonation token, if any\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Operations on access tokens:\n"));
   _ftprintf(stderr, TEXT("   --show-token                  display user, groups, privileges, etc.\n"));
   _ftprintf(stderr, TEXT("   -e --enable-priv  <name>      enable a disabled privilege (use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   -d --disable-priv <name>      disable an enabled privilege (use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   --remove-priv     <name>      remove a privilege entirely (cannot be undone, use * as wildcard)\n"));
   _ftprintf(stderr, TEXT("   --assign <tid>                set the given thread's impersonation token to be the selected token\n"));
   _ftprintf(stderr, TEXT("   --impersonate                 impersonate the selected token for operations that follow\n"));
   _ftprintf(stderr, TEXT("                                 (requires SeImpersonatePrivilege)\n"));
   _ftprintf(stderr, TEXT("   --stop-impersonating          stop impersonating for operations that follow\n"));
   _ftprintf(stderr, TEXT("   -x --execute <cmd>            create a process executing that command, with the selected token\n"));
   _ftprintf(stderr, TEXT("                                 (requires SeAssignPrimaryTokenPrivilege)\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Enumerate objects with a given criteria (doesn't select any of them) (mostly useful while impersonating a token):\n"));
   _ftprintf(stderr, TEXT("   --files-with <access_right>                 shows all files on which we have the given access right\n"));
   _ftprintf(stderr, TEXT("   --regkey-with <access_right>                shows all registry keys on which we have the given access right\n"));
   _ftprintf(stderr, TEXT("   --proc-with <access_right|sid|privilege>    shows all processes on which we have the given access right, or who\n"));
   _ftprintf(stderr, TEXT("                                               hold a primary token containing the given SID or privilege name\n"));
   _ftprintf(stderr, TEXT("   --thread-with <access_right|sid|privilege>  shows all threads on which we have the given access right, or who\n"));
   _ftprintf(stderr, TEXT("                                               hold an impersonation token containing the given SID or privilege name\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Convenience functions to pretty print security descriptors:\n"));
   _ftprintf(stderr, TEXT("   --explain-sd [<type>:]<sddl>  describe as text the given security descriptor definition language\n"));
   _ftprintf(stderr, TEXT("\n"));
   _ftprintf(stderr, TEXT("Options:\n"));
   _ftprintf(stderr, TEXT("   -y --yes                      don't prompt for consent, assume yes\n"));
   _ftprintf(stderr, TEXT("   -n --no                       don't prompt for consent, assume no\n"));
   _ftprintf(stderr, TEXT("   -v --verbose                  increase verbosity (can be repeated)\n"));
   _ftprintf(stderr, TEXT("   -h --help                     display this help text\n"));
   _ftprintf(stderr, TEXT("   -V --version                  display the current version\n"));
   _ftprintf(stderr, TEXT("\n"));
}

int _tmain(int argc, PCTSTR argv[])
{
   int res = 0;
   target_t targetType = TARGET_PROCESS;
   PCTSTR swzTarget = TEXT("caller");

   resolve_imports();

   if (argc < 2)
   {
      res = 1;
      print_usage();
      goto cleanup;
   }

   set_privilege_caller(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_SECURITY_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED);
   set_privilege_caller(SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED);

   for (int argn = 1; argn < argc; argn++)
   {
      PCTSTR arg = argv[argn];
      if (_tcsicmp(TEXT("-h"), arg) == 0 || _tcsicmp(TEXT("-?"), arg) == 0 || _tcsicmp(TEXT("--help"), arg) == 0)
      {
         res = 1;
         print_usage();
         goto cleanup;
      }
      else if (_tcsicmp(TEXT("-V"), arg) == 0 || _tcsicmp(TEXT("--version"), arg) == 0)
      {
         res = 1;
         print_version();
         goto cleanup;
      }
      else if (_tcsicmp(TEXT("-p"), arg) == 0 || _tcsicmp(TEXT("--process"), arg) == 0)
      {
         if (argn == argc - 1 || argv[argn + 1][0] == TEXT('-'))
         {
            res = 1;
            _ftprintf(stderr, TEXT(" [!] Error: option --process requires a PID or image name\n"));
            print_usage();
            goto cleanup;
         }
         swzTarget = argv[++argn];
         targetType = TARGET_PROCESS;
      }
      else if (_tcsicmp(TEXT("-t"), arg) == 0 || _tcsicmp(TEXT("--thread"), arg) == 0)
      {
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --thread requires a TID\n"));
            print_usage();
            goto cleanup;
         }
         swzTarget = argv[++argn];
         targetType = TARGET_THREAD;
      }
      else if (_tcsicmp(TEXT("-r"), arg) == 0 || _tcsicmp(TEXT("--regkey"), arg) == 0)
      {
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --regkey requires an absolute path\n"));
            print_usage();
            goto cleanup;
         }
         swzTarget = argv[++argn];
         targetType = TARGET_REGKEY;
      }
      else if (_tcsicmp(TEXT("-f"), arg) == 0 || _tcsicmp(TEXT("--file"), arg) == 0)
      {
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --file requires a Win32 or NT path\n"));
            print_usage();
            goto cleanup;
         }
         swzTarget = argv[++argn];
         targetType = TARGET_FILE;
      }
      else if (_tcsicmp(TEXT("-k"), arg) == 0 || _tcsicmp(TEXT("--kernobj"), arg) == 0)
      {
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --kernobj requires an absolute NT path\n"));
            print_usage();
            goto cleanup;
         }
         swzTarget = argv[++argn];
         targetType = TARGET_KERNEL_OBJECT;
      }
      else if (_tcsicmp(TEXT("--show-sddl"), arg) == 0)
      {
         res = do_show_sd(targetType, swzTarget, FALSE);
         if (res != 0)
            goto cleanup;
      }
      else if (_tcsicmp(TEXT("--show-sd"), arg) == 0)
      {
         res = do_show_sd(targetType, swzTarget, TRUE);
         if (res != 0)
            goto cleanup;
      }
      else if (_tcsicmp(TEXT("--show-token"), arg) == 0)
      {
         HANDLE hToken = INVALID_HANDLE_VALUE;
         res = get_target_token(swzTarget, targetType, TOKEN_QUERY, &hToken);
         if (res != 0)
            goto cleanup;
         print_token(hToken);
      }
      else if (_tcsicmp(TEXT("--open-token"), arg) == 0)
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
            _ftprintf(stderr, TEXT(" [!] Error: cannot open token, selected target must be a process or thread\n"));
            print_usage();
            goto cleanup;
         }
      }
      else if (_tcsicmp(TEXT("-e"), arg) == 0 || _tcsicmp(TEXT("--enable-priv"), arg) == 0)
      {
         PCTSTR swzPrivName = NULL;
         HANDLE hToken = INVALID_HANDLE_VALUE;
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --enable-priv requires a privilege name or wildcard\n"));
            print_usage();
            goto cleanup;
         }
         swzPrivName = argv[++argn];
         res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
         if (res != 0)
            goto cleanup;
         res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_ENABLED);
         if (res != 0)
            goto cleanup;
         _tprintf(TEXT(" [.] Privilege %s enabled\n"), swzPrivName);
      }
      else if (_tcsicmp(TEXT("-d"), arg) == 0 || _tcsicmp(TEXT("--disable-priv"), arg) == 0)
      {
         PCTSTR swzPrivName = NULL;
         HANDLE hToken = INVALID_HANDLE_VALUE;
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --disable-priv requires a privilege name or wildcard\n"));
            print_usage();
            goto cleanup;
         }
         swzPrivName = argv[++argn];
         res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
         if (res != 0)
            goto cleanup;
         res = set_privilege(hToken, swzPrivName, 0);
         if (res != 0)
            goto cleanup;
         _tprintf(TEXT(" [.] Privilege %s disabled\n"), swzPrivName);
      }
      else if (_tcsicmp(TEXT("--remove-priv"), arg) == 0)
      {
         PCTSTR swzPrivName = NULL;
         HANDLE hToken = INVALID_HANDLE_VALUE;
         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --remove-priv requires a privilege name or wildcard\n"));
            print_usage();
            goto cleanup;
         }
         swzPrivName = argv[++argn];
         res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
         if (res != 0)
            goto cleanup;
         res = set_privilege(hToken, swzPrivName, SE_PRIVILEGE_REMOVED);
         if (res != 0)
            goto cleanup;
         _tprintf(TEXT(" [.] Privilege %s removed\n"), swzPrivName);
      }
      else if (_tcsicmp(TEXT("--assign"), arg) == 0)
      {
         HANDLE hThread = INVALID_HANDLE_VALUE;
         HANDLE hToken = INVALID_HANDLE_VALUE;
         PCTSTR swzTargetThread = NULL;

         if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --assign requires a privilege name or wildcard\n"));
            print_usage();
            goto cleanup;
         }
         swzTargetThread = argv[++argn];

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
         _tprintf(TEXT(" [.] Token assigned to thread %s\n"), swzTargetThread);
      }
      else if (_tcsicmp(TEXT("--impersonate"), arg) == 0)
      {
         HANDLE hToken = INVALID_HANDLE_VALUE;
         HANDLE hImpersToken = INVALID_HANDLE_VALUE;
         res = get_target_token(swzTarget, targetType, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
         if (res != 0)
            goto cleanup;
         if (!DuplicateToken(hToken, SecurityImpersonation, &hImpersToken))
         {
            res = GetLastError();
            _ftprintf(stderr, TEXT(" [!] Error: duplicating token for impersonation failed with code %u\n"), res);
            goto cleanup;
         }
         res = set_privilege_caller(SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED);
         if (res != 0)
            goto cleanup;
         if (!ImpersonateLoggedOnUser(hImpersToken))
         {
            res = GetLastError();
            _ftprintf(stderr, TEXT(" [!] Error: impersonation failed with code %u\n"), res);
            goto cleanup;
         }
         _tprintf(TEXT(" [.] Impersonating token temporarily\n"));
      }
      else if (_tcsicmp(TEXT("--stop-impersonating"), arg) == 0)
      {
         if (!RevertToSelf())
         {
            res = GetLastError();
            _ftprintf(stderr, TEXT(" [!] Error: reverting impersonation failed with code %u\n"), res);
            goto cleanup;
         }
         _tprintf(TEXT(" [.] Stopped impersonating token\n"));
      }
      else if (_tcsicmp(TEXT("--steal-token"), arg) == 0)
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
            _ftprintf(stderr, TEXT(" [!] Error: option --steal-token only works with a target process selected\n"));
            print_usage();
            goto cleanup;
         }
         else if (argn == argc - 1)
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --steal-token requires a command to execute\n"));
            print_usage();
            goto cleanup;
         }
         swzTargetCommand = (PTSTR)argv[++argn];

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
         _tprintf(TEXT(" [.] Token stolen by child process %u executing %s\n"), procInfo.dwProcessId, swzTargetCommand);
      }
      else
      {
         res = -1;
         _ftprintf(stderr, TEXT(" [!] Error: invalid argument '%s'\n"), arg);
         goto cleanup;
      }
   }

   cleanup:
   if (verbosity > 0)
   _tprintf(TEXT(" [.] Exiting with code %d\n"), res);
   return res;
}