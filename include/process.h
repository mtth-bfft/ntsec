#pragma once
#include <Windows.h>
#include "include\targets.h"

int create_process_with_token(HANDLE hToken, PTSTR swzCommandLine, PHANDLE phNewProcess);
int create_reparented_process(HANDLE hParentProcess, PTSTR swzCommandLine, PHANDLE phNewProcess);
int open_nt_process_object(PCTSTR swzTarget, target_t *pTargetType, DWORD dwRightsRequired, PHANDLE phOut);
int open_nt_process_by_pid(DWORD dwPID, DWORD dwRightsRequired, PHANDLE phOut);
int find_process_by_name(PCTSTR swzName, DWORD *pdwPID);
int enumerate_processes_with(DWORD dwDesiredAccess);
int list_memmap(HANDLE hProcess);
