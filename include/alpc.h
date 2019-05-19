#pragma once
#include <Windows.h>

int enumerate_alpc_ports_with(DWORD dwDesiredAccess);
int open_nt_alpcconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
