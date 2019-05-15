#pragma once
#include <Windows.h>

int open_process(DWORD dwPID, DWORD dwRightsRequired, PHANDLE phOut);
int find_process_by_name(PCTSTR swzName, DWORD *pdwPID);
int enumerate_processes_with(DWORD dwDesiredAccess);
int list_memmap(HANDLE hProcess);
