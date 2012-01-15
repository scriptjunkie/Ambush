#pragma once
#include "signatures.h"
#ifdef _M_X64
#include "apihookx64.h"
#else
#include "apihookx86.h"
#endif

extern HANDLE rwHeap;
extern HMODULE myDllHandle;
extern HOOKAPI_CONF * apiConf;

#define LOCAL_REPORT_PIPE "\\\\.\\pipe\\FunctionFilterReport"
#define REPORT_FILE "FFlog.txt"
#define MAX_ARGS 64 // should be enough for anybody - 
//note this simply ignores arguments past MAX_ARGS not crashes or overflows

#define NO_PROC_MATCH (slre*)-2
#define PROC_MATCH (slre*)-1

#ifdef _M_X64
#pragma pack(push,8)
#else
#pragma pack(push,4)
#endif
typedef struct sHOOKAPI_MESSAGE
{
    DWORD   length; // of entire message
    DWORD   type;   // what action is firing
    DWORD   pid;
    DWORD   count;
    DWORD   numArgs;
} HOOKAPI_MESSAGE, *PHOOKAPI_MESSAGE;
//tests whether messages are equal other than the count
inline bool messageEqual(PHOOKAPI_MESSAGE first, PHOOKAPI_MESSAGE second){
	DWORD firstCount = first->count; //Save counts
	first->count = second->count; //Make counts the same
	//Do the compare
	bool retval = first->length == second->length && memcmp(first, second, first->length) == 0;
	first->count = firstCount; //Reset the count
	return retval;
}

//Functions
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL hookDllApi(HMODULE dllHandle);

//Types for dynamic function definitions
typedef void* (WINAPI *NoArgFunc)();
typedef HMODULE (WINAPI *OneArgFunc)(void*); //For LoadLibrary
typedef HMODULE (WINAPI *ThreeArgFunc)(void*,void*,void*); //For LoadLibraryEx
typedef void** (WINAPI *hookArgFunc)();

//MICROSOFT DEFINES from MSDN - because my local win SDK does not have a complete set
/*
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
*/
typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
   PVOID Reserved1[2];
   LIST_ENTRY InMemoryOrderLinks;
   PVOID Reserved2[2];
   PVOID DllBase;
   PVOID EntryPoint;
   PVOID Reserved3;
   UNICODE_STRING FullDllName;
   BYTE Reserved4[8];
   PVOID Reserved5[3];
   union {
       ULONG CheckSum;
       PVOID Reserved6;
   };
   ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
 BYTE       Reserved1[8];
 PVOID      Reserved2[3];
 LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
 BYTE                          Reserved1[2];
 BYTE                          BeingDebugged;
 BYTE                          Reserved2[1];
 PVOID                         Reserved3[2];
 PPEB_LDR_DATA                 Ldr;
 PVOID  ProcessParameters;
 BYTE                          Reserved4[104];
 PVOID                         Reserved5[52];
 PVOID   PostProcessInitRoutine;
 BYTE                          Reserved6[128];
 PVOID                         Reserved7[1];
 ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *NtQueryInformationProcessFunc)(
  __in       HANDLE ProcessHandle,
  __in       DWORD ProcessInformationClass,
  __out      PVOID ProcessInformation,
  __in       ULONG ProcessInformationLength,
  __out_opt  PULONG ReturnLength
);

#pragma pack(pop)
