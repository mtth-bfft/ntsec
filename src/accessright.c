#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <sddl.h>
#include "accessright.h"

enum
{
   ADS_RIGHT_DELETE = 0x10000,
   ADS_RIGHT_READ_CONTROL = 0x20000,
   ADS_RIGHT_WRITE_DAC = 0x40000,
   ADS_RIGHT_WRITE_OWNER = 0x80000,
   ADS_RIGHT_SYNCHRONIZE = 0x100000,
   ADS_RIGHT_ACCESS_SYSTEM_SECURITY = 0x1000000,
   ADS_RIGHT_GENERIC_READ = 0x80000000,
   ADS_RIGHT_GENERIC_WRITE = 0x40000000,
   ADS_RIGHT_GENERIC_EXECUTE = 0x20000000,
   ADS_RIGHT_GENERIC_ALL = 0x10000000,
   ADS_RIGHT_DS_CREATE_CHILD = 0x1,
   ADS_RIGHT_DS_DELETE_CHILD = 0x2,
   ADS_RIGHT_ACTRL_DS_LIST = 0x4,
   ADS_RIGHT_DS_SELF = 0x8,
   ADS_RIGHT_DS_READ_PROP = 0x10,
   ADS_RIGHT_DS_WRITE_PROP = 0x20,
   ADS_RIGHT_DS_DELETE_TREE = 0x40,
   ADS_RIGHT_DS_LIST_OBJECT = 0x80,
   ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
}  ADS_RIGHTS_ENUM;

PCTSTR pAccessRights[][5] = {
   // Generic access rights
   { (PCTSTR) GENERIC_READ,                TEXT("GENERIC_READ"),            TEXT("GR"),  NULL,         NULL },
   { (PCTSTR) GENERIC_WRITE,               TEXT("GENERIC_WRITE"),           TEXT("GW"),  NULL,         NULL },
   { (PCTSTR) GENERIC_EXECUTE,             TEXT("GENERIC_EXECUTE"),         TEXT("GE"),  NULL,         NULL },
   { (PCTSTR) GENERIC_ALL,                 TEXT("GENERIC_ALL"),             TEXT("GA"),  NULL,         NULL },
   { (PCTSTR) ACCESS_SYSTEM_SECURITY,      TEXT("ACCESS_SYSTEM_SECURITY"),  TEXT("AS"),  NULL,         NULL },
   // Standard access rights
   { (PCTSTR) DELETE,                      TEXT("DELETE"),                  TEXT("SD"),  NULL,         NULL },
   { (PCTSTR) READ_CONTROL,                TEXT("READ_CONTROL"),            TEXT("SD"),  NULL,         NULL },
   { (PCTSTR) SYNCHRONIZE,                 TEXT("SYNCHRONIZE"),             NULL,        NULL,         NULL },
   { (PCTSTR) WRITE_DAC,                   TEXT("WRITE_DAC"),               TEXT("WD"),  NULL,         NULL },
   { (PCTSTR) WRITE_OWNER,                 TEXT("WRITE_OWNER"),             TEXT("WO"),  NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_ALL,         TEXT("STANDARD_RIGHTS_ALL"),     NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_EXECUTE,     TEXT("STANDARD_RIGHTS_EXECUTE"), NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_READ,        TEXT("STANDARD_RIGHTS_READ"),    NULL,        NULL,         NULL },
   { (PCTSTR) STANDARD_RIGHTS_WRITE,       TEXT("STANDARD_RIGHTS_WRITE"),   NULL,        NULL,         NULL },
   // Directory Services specific object rights
   { (PCTSTR) ADS_RIGHT_DS_CREATE_CHILD,   TEXT("CREATE_CHILD"),            TEXT("CC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_DELETE_CHILD,   TEXT("DELETE_CHILD"),            TEXT("DC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_ACTRL_DS_LIST,     TEXT("ACTRL_DS_LIST"),           TEXT("LC"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_SELF,           TEXT("SELF_WRITE"),              TEXT("SW"),  TEXT("SELF"), NULL },
   { (PCTSTR) ADS_RIGHT_DS_READ_PROP,      TEXT("READ_PROP"),               TEXT("RP"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_WRITE_PROP,     TEXT("WRITE_PROP"),              TEXT("WP"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_DELETE_TREE,    TEXT("DELETE_TREE"),             TEXT("DT"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_LIST_OBJECT,    TEXT("LIST_OBJECT"),             TEXT("LO"),  NULL,         NULL },
   { (PCTSTR) ADS_RIGHT_DS_CONTROL_ACCESS, TEXT("CONTROL_ACCESS"),          TEXT("CR"),  NULL,         NULL },
   // File specific rights
   { (PCTSTR) FILE_READ_DATA,              TEXT("FILE_READ_DATA"),          NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_DATA,             TEXT("FILE_WRITE_DATA"),         NULL,        NULL,         NULL },
   { (PCTSTR) FILE_APPEND_DATA,            TEXT("FILE_APPEND_DATA"),        NULL,        NULL,         NULL },
   { (PCTSTR) FILE_READ_EA,                TEXT("FILE_READ_EA"),            NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_EA,               TEXT("FILE_WRITE_EA"),           NULL,        NULL,         NULL },
   { (PCTSTR) FILE_EXECUTE,                TEXT("FILE_EXECUTE"),            NULL,        NULL,         NULL },
   { (PCTSTR) FILE_READ_ATTRIBUTES,        TEXT("FILE_READ_ATTRIBUTES"),    NULL,        NULL,         NULL },
   { (PCTSTR) FILE_WRITE_ATTRIBUTES,       TEXT("FILE_WRITE_ATTRIBUTES"),   NULL,        NULL,         NULL },
   { (PCTSTR) FILE_ALL_ACCESS,             TEXT("FILE_ALL_ACCESS"),         NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_READ,           TEXT("FILE_GENERIC_READ"),       NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_WRITE,          TEXT("FILE_GENERIC_WRITE"),      NULL,        NULL,         NULL },
   { (PCTSTR) FILE_GENERIC_EXECUTE,        TEXT("FILE_GENERIC_EXECUTE"),    NULL,        NULL,         NULL },
};

static int parse_single_access_right(PTSTR swzDesiredAccess, PDWORD pdwDesiredAccess)
{
   for (size_t i = 0; i < sizeof(pAccessRights) / sizeof(pAccessRights[0]); i++)
   {
      if (_tcsicmp(pAccessRights[i][1], swzDesiredAccess) == 0)
      {
         *pdwDesiredAccess = (DWORD)pAccessRights[i][0];
         return 0;
      }
   }
   return ERROR_INVALID_PARAMETER;
}

int parse_access_right(PTSTR swzDesiredAccess, PDWORD pdwDesiredAccess)
{
   int res = 0;
   PTSTR pContext = NULL;
   PTSTR swzChunk = NULL;
   DWORD dwDesiredAccess = 0;

   swzChunk = _tcstok_s(swzDesiredAccess, TEXT("|"), &pContext);
   while (swzChunk != NULL)
   {
      DWORD dwSingleRight = 0;
      res = parse_single_access_right(swzChunk, &dwSingleRight);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Unable to parse access right '%s'\n"), swzChunk);
         goto cleanup;
      }
      dwDesiredAccess |= dwSingleRight;
      swzChunk = _tcstok_s(NULL, TEXT("|"), &pContext);
   }

   *pdwDesiredAccess = dwDesiredAccess;

cleanup:
   return res;
}