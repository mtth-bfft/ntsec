#pragma once
#include <Windows.h>
#include <subauth.h>

// This file handles the NT-specific-and-internal aspects
// These structures and functions are mostly undocumented and can change from one release to the next

#define FILE_OPEN_IF 0x00000003
#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_NO_MORE_FILES 0x80000006

typedef enum _SYSTEM_INFORMATION_CLASS {
   SystemHandleInformation = 0x10,
} SYSTEM_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
   FileDirectoryInformation = 1,
   FileFullDirectoryInformation,
   FileBothDirectoryInformation,
   FileBasicInformation,
   FileStandardInformation,
   FileInternalInformation,
   FileEaInformation,
   FileAccessInformation,
   FileNameInformation,
   FileRenameInformation,
   FileLinkInformation,
   FileNamesInformation,
   FileDispositionInformation,
   FilePositionInformation,
   FileFullEaInformation,
   FileModeInformation,
   FileAlignmentInformation,
   FileAllInformation,
   FileAllocationInformation,
   FileEndOfFileInformation,
   FileAlternateNameInformation,
   FileStreamInformation,
   FilePipeInformation,
   FilePipeLocalInformation,
   FilePipeRemoteInformation,
   FileMailslotQueryInformation,
   FileMailslotSetInformation,
   FileCompressionInformation,
   FileCopyOnWriteInformation,
   FileCompletionInformation,
   FileMoveClusterInformation,
   FileQuotaInformation,
   FileReparsePointInformation,
   FileNetworkOpenInformation,
   FileObjectIdInformation,
   FileTrackingInformation,
   FileOleDirectoryInformation,
   FileContentIndexInformation,
   FileInheritContentIndexInformation,
   FileOleInformation,
   FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_DIRECTORY_INFORMATION {
   ULONG         NextEntryOffset;
   ULONG         FileIndex;
   LARGE_INTEGER CreationTime;
   LARGE_INTEGER LastAccessTime;
   LARGE_INTEGER LastWriteTime;
   LARGE_INTEGER ChangeTime;
   LARGE_INTEGER EndOfFile;
   LARGE_INTEGER AllocationSize;
   ULONG         FileAttributes;
   ULONG         FileNameLength;
   WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
   UNICODE_STRING Name;
   UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
   ULONG           Length;
   HANDLE          RootDirectory;
   PUNICODE_STRING ObjectName;
   ULONG           Attributes;
   PVOID           SecurityDescriptor;
   PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
   union {
      NTSTATUS Status;
      PVOID    Pointer;
   } _result;
   ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
   ULONG ProcessId;
   BYTE ObjectTypeNumber;
   BYTE Flags;
   USHORT Handle;
   PVOID Object;
   ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
   ULONG HandleCount;
   SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI *PNtOpenDirectoryObject)(
   _Out_ PHANDLE            DirectoryHandle,
   _In_  ACCESS_MASK        DesiredAccess,
   _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtQueryDirectoryObject)(
   _In_      HANDLE  DirectoryHandle,
   _Out_opt_ PVOID   Buffer,
   _In_      ULONG   Length,
   _In_      BOOLEAN ReturnSingleEntry,
   _In_      BOOLEAN RestartScan,
   _Inout_   PULONG  Context,
   _Out_opt_ PULONG  ReturnLength);

typedef NTSTATUS(WINAPI *PNtOpenFile)(
   PHANDLE            FileHandle,
   ACCESS_MASK        DesiredAccess,
   POBJECT_ATTRIBUTES ObjectAttributes,
   PIO_STATUS_BLOCK   IoStatusBlock,
   ULONG              ShareAccess,
   ULONG              OpenOptions);

typedef NTSTATUS(WINAPI *PNtQueryDirectoryFile)(
   HANDLE                 FileHandle,
   HANDLE                 Event,
   PVOID                  ApcRoutine,
   PVOID                  ApcContext,
   PIO_STATUS_BLOCK       IoStatusBlock,
   PVOID                  FileInformation,
   ULONG                  Length,
   FILE_INFORMATION_CLASS FileInformationClass,
   BOOLEAN                ReturnSingleEntry,
   PUNICODE_STRING        FileName,
   BOOLEAN                RestartScan);

typedef NTSTATUS(WINAPI *PNtOpenSymbolicLinkObject)(
   _Out_ PHANDLE            LinkHandle,
   _In_  ACCESS_MASK        DesiredAccess,
   _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenMutant)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenEvent)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSection)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSemaphore)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenTimer)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSession)(
   OUT PHANDLE             MutantHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
   OUT PVOID                   SystemInformation,
   IN ULONG                    SystemInformationLength,
   OUT PULONG                  ReturnLength
);

// ALPC types and imports

typedef struct _CLIENT_ID {
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _ALPC_PORT_ATTRIBUTES
{
   ULONG Flags;
   SECURITY_QUALITY_OF_SERVICE SecurityQos;
   SIZE_T MaxMessageLength;
   SIZE_T MemoryBandwidth;
   SIZE_T MaxPoolUsage;
   SIZE_T MaxSectionSize;
   SIZE_T MaxViewSize;
   SIZE_T MaxTotalSectionSize;
   ULONG DupObjectTypes;
   ULONG Reserved;
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
   union
   {
      struct
      {
         SHORT DataLength;
         SHORT TotalLength;
      } s1;
      ULONG Length;
   } u1;
   union
   {
      struct
      {
         SHORT Type;
         SHORT DataInfoOffset;
      } s2;
      ULONG ZeroInit;
   } u2;
   union
   {
      CLIENT_ID ClientId;
      double DoNotUseThisField;
   } u3;
   ULONG MessageId;
   union
   {
      SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
      ULONG CallbackId; // only valid for LPC_REQUEST messages
   } u4;
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
   ULONG AllocatedAttributes;
   ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef NTSTATUS(WINAPI *PNtAlpcConnectPort)(
   _Out_ PHANDLE PortHandle,
   _In_ PUNICODE_STRING PortName,
   _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
   _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
   _In_ ULONG Flags,
   _In_opt_ PSID RequiredServerSid,
   _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
   _Inout_opt_ PULONG BufferLength,
   _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
   _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
   _In_opt_ PLARGE_INTEGER Timeout);

// Our custom types

typedef enum {
   TARGET_NONE = 0,
   TARGET_PROCESS,
   TARGET_THREAD,
   TARGET_PRIMARY_TOKEN,
   TARGET_IMPERSONATION_TOKEN,
   TARGET_REGKEY,
   TARGET_FILE,
   TARGET_NT_OBJECT,
} target_t;

typedef enum {
   NT_UNKNOWN = 0,
   NT_DIRECTORY,
} nt_object_type_t;

typedef int(*nt_object_open_t)(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
typedef int(*nt_object_enum_callback_t)(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData);
typedef int(*nt_file_enum_callback_t)(PCTSTR swzNtPath, PVOID pData);

extern PNtOpenDirectoryObject NtOpenDirectoryObject;
extern PNtQueryDirectoryObject NtQueryDirectoryObject;
extern PNtOpenFile NtOpenFile;
extern PNtQueryDirectoryFile NtQueryDirectoryFile;
extern PNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject;
extern PNtOpenMutant NtOpenMutant;
extern PNtOpenEvent NtOpenEvent;
extern PNtOpenSection NtOpenSection;
extern PNtOpenSemaphore NtOpenSemaphore;
extern PNtOpenTimer NtOpenTimer;
extern PNtOpenSession NtOpenSession;
extern PNtAlpcConnectPort NtAlpcConnectPort;
extern PNtQuerySystemInformation NtQuerySystemInformation;

int resolve_imports();
int open_target(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_file_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_symbolic_link_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_mutant_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_event_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_section_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_semaphore_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_timer_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_session_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_filterconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_alpcconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_unsupported_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int foreach_nt_object(PCTSTR swzNTPath, nt_object_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
int foreach_nt_directory_files(PCTSTR swzDirectoryFileNTPath, nt_file_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
int enumerate_nt_objects_with(DWORD dwDesiredAccess);
int get_handle_granted_rights(HANDLE hHandle, PDWORD pdwGrantedRights);
