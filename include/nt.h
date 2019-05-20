#pragma once
#include <Windows.h>
#include <subauth.h>
#include "include\targets.h"

// This file handles the NT-specific-and-internal aspects
// These structures and functions are mostly undocumented and can change from one release to the next

#define FILE_OPEN 0x00000001
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE    0x00000040L

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_NO_MORE_FILES 0x80000006
#define STATUS_NO_MORE_ENTRIES  0x8000001AL
#define STATUS_NOT_A_DIRECTORY 0xC0000103

#define InitializeObjectAttributes( p, n, a, r, s ) { \
   (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
   (p)->RootDirectory = r;                             \
   (p)->Attributes = a;                                \
   (p)->ObjectName = n;                                \
   (p)->SecurityDescriptor = s;                        \
   (p)->SecurityQualityOfService = NULL;               \
   }

typedef enum _SYSTEM_INFORMATION_CLASS {
   SystemHandleInformation = 0x10,
} SYSTEM_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS {
   KeyBasicInformation,
   KeyNodeInformation,
   KeyFullInformation,
   KeyNameInformation,
   KeyCachedInformation,
   KeyFlagsInformation,
   KeyVirtualizationInformation,
   KeyHandleTagsInformation,
   KeyTrustInformation,
   KeyLayerInformation,
   MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

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

typedef enum {
   ObjectBasicInformation = 0,
   ObjectNameInformation = 1,
   ObjectTypeInformation = 2,
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
   UNICODE_STRING TypeName;
   ULONG          Reserved[22];
   BYTE           Reserved2[1024];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
   ULONG       Attributes;
   ACCESS_MASK GrantedAccess;
   ULONG       HandleCount;
   ULONG       PointerCount;
   ULONG       Reserved[10];
} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
   LARGE_INTEGER LastWriteTime;
   ULONG         TitleIndex;
   ULONG         NameLength;
   WCHAR         Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

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

typedef NTSTATUS(WINAPI *PNtCreateFile)(
   OUT PHANDLE           FileHandle,
   IN ACCESS_MASK        DesiredAccess,
   IN POBJECT_ATTRIBUTES ObjectAttributes,
   OUT PIO_STATUS_BLOCK  IoStatusBlock,
   IN PLARGE_INTEGER     AllocationSize,
   IN ULONG              FileAttributes,
   IN ULONG              ShareAccess,
   IN ULONG              CreateDisposition,
   IN ULONG              CreateOptions,
   IN PVOID              EaBuffer,
   IN ULONG              EaLength
);

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
   _Out_ PHANDLE            Handle,
   _In_  ACCESS_MASK        DesiredAccess,
   _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenMutant)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenEvent)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenKeyedEvent)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSection)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSemaphore)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenTimer)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenSession)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenJobObject)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenPartition)(
   OUT PHANDLE             Handle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes);

typedef NTSTATUS(WINAPI *PNtOpenKeyEx)(
   OUT PHANDLE             KeyHandle,
   IN ACCESS_MASK          DesiredAccess,
   IN POBJECT_ATTRIBUTES   ObjectAttributes,
   IN ULONG                OpenOptions);

typedef NTSTATUS(WINAPI *PNtEnumerateKey)(
   IN HANDLE                KeyHandle,
   IN ULONG                 Index,
   IN KEY_INFORMATION_CLASS KeyInformationClass,
   OUT PVOID                KeyInformation,
   IN ULONG                 Length,
   OUT PULONG               ResultLength);

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
   OUT PVOID                   SystemInformation,
   IN ULONG                    SystemInformationLength,
   OUT PULONG                  ReturnLength);

typedef NTSTATUS(WINAPI *PNtQueryObject)(
   IN  HANDLE                   Handle,
   IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
   OUT PVOID                    ObjectInformation,
   IN  ULONG                    ObjectInformationLength,
   OUT PULONG                   ReturnLength);

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

typedef int(*nt_path_enum_callback_t)(PCTSTR swzNtPath, PVOID pData);

extern PNtOpenDirectoryObject NtOpenDirectoryObject;
extern PNtQueryDirectoryObject NtQueryDirectoryObject;
extern PNtCreateFile NtCreateFile;
extern PNtQueryDirectoryFile NtQueryDirectoryFile;
extern PNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject;
extern PNtOpenMutant NtOpenMutant;
extern PNtOpenEvent NtOpenEvent;
extern PNtOpenKeyedEvent NtOpenKeyedEvent;
extern PNtOpenSection NtOpenSection;
extern PNtOpenSemaphore NtOpenSemaphore;
extern PNtOpenTimer NtOpenTimer;
extern PNtOpenSession NtOpenSession;
extern PNtOpenJobObject NtOpenJobObject;
extern PNtOpenPartition NtOpenPartition;
extern PNtOpenKeyEx NtOpenKeyEx;
extern PNtEnumerateKey NtEnumerateKey;
extern PNtAlpcConnectPort NtAlpcConnectPort;
extern PNtQuerySystemInformation NtQuerySystemInformation;
extern PNtQueryObject NtQueryObject;

int resolve_imports();
int get_handle_granted_rights(HANDLE hHandle, PDWORD pdwGrantedRights);
int get_nt_object_type(PCTSTR swzNTPath, target_t *pType);
