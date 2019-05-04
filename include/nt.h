#pragma once
#include <Windows.h>
#include <subauth.h>

// This file handles the NT-specific-and-internal aspects
// These structures and functions are mostly undocumented and can change from one release to the next

#define FILE_OPEN_IF 0x00000003
#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_NO_MORE_FILES 0x80000006

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
   ULONG              OpenOptions
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
   BOOLEAN                RestartScan
   );

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

typedef int(*nt_object_enum_callback_t)(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData);
typedef int(*nt_file_enum_callback_t)(PCTSTR swzNtPath, PVOID pData);

extern PNtOpenDirectoryObject NtOpenDirectoryObject;
extern PNtQueryDirectoryObject NtQueryDirectoryObject;
extern PNtOpenFile NtOpenFile;
extern PNtQueryDirectoryFile NtQueryDirectoryFile;

int resolve_imports();
int open_target(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int open_nt_file_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int foreach_nt_object(PCTSTR swzNTPath, nt_object_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
int foreach_nt_directory_files(PCTSTR swzDirectoryFileNTPath, nt_file_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
