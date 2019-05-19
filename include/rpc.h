#pragma once
#include <Windows.h>
#include <tchar.h>

int list_rpcs_mapped();
int list_rpc_named_pipe(PCTSTR swzNamedPipe);
int list_rpc_alpc(PCTSTR swzALPCPortNTPath);
