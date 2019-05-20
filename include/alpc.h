#pragma once
#include <Windows.h>
#include "include\targets.h"

int enumerate_alpc_ports_with(DWORD dwDesiredAccess);
int open_nt_alpcconnectionport_object(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut);
