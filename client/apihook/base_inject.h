//===============================================================================================//
#ifndef _BASE_INJECT_H
#define _BASE_INJECT_H
//===============================================================================================//
#include <Tlhelp32.h>

#define PROCESS_ARCH_UNKNOWN				0
#define PROCESS_ARCH_X86					1
#define PROCESS_ARCH_X64					2
#define PROCESS_ARCH_IA64					3

// The three injection techniques currently supported.
#define INJECT_TECHNIQUE_REMOTETHREAD		0
#define INJECT_TECHNIQUE_REMOTETHREADWOW64	1
#define INJECT_TECHNIQUE_APCQUEUE			2

//===============================================================================================//

// Definition of ntdll!NtQueueApcThread
typedef NTSTATUS (NTAPI * NTQUEUEAPCTHREAD)( HANDLE hThreadHandle, LPVOID lpApcRoutine, LPVOID lpApcRoutineContext, LPVOID lpApcStatusBlock, LPVOID lpApcReserved );

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

typedef DWORD (WINAPI * GETMODULEFILENAMEEXA)( HANDLE hProcess, HMODULE hModule, LPTSTR lpExeName, DWORD dwSize );
typedef DWORD (WINAPI * GETPROCESSIMAGEFILENAMEA)( HANDLE hProcess, LPTSTR lpExeName, DWORD dwSize );
typedef BOOL (WINAPI * QUERYFULLPROCESSIMAGENAMEA)( HANDLE hProcess, DWORD dwFlags, LPTSTR lpExeName, PDWORD lpdwSize );
typedef HANDLE (WINAPI * CREATETOOLHELP32SNAPSHOT)( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL (WINAPI * PROCESS32FIRST)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL (WINAPI * PROCESS32NEXT)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );
typedef BOOL (WINAPI * ISWOW64PROCESS)( HANDLE hProcess, PBOOL Wow64Process );

typedef NTSTATUS (WINAPI * NTQUERYINFORMATIONPROCESS)( HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );

typedef BOOL (WINAPI * ENUMPROCESSES)( DWORD * pProcessIds, DWORD cb, DWORD * pBytesReturned );
typedef BOOL (WINAPI * ENUMPROCESSMODULES)( HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded );
typedef DWORD (WINAPI * GETMODULEBASENAMEA)( HANDLE hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize );


//===============================================================================================//

// The context used for injection via inject_via_apcthread
typedef struct _APCCONTEXT
{
 	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8]; 
	} s;

	union
	{
 		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;

	BYTE bExecuted;

} APCCONTEXT, * LPAPCCONTEXT;

// The context used for injection via inject_via_remotethread_wow64
typedef struct _WOW64CONTEXT
{
	union
	{
 		HANDLE hProcess;
		BYTE bPadding2[8];
	} h;

 	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8]; 
	} s;

	union
	{
 		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;
	union
	{
		HANDLE hThread;
		BYTE bPadding2[8];
	} t;
} WOW64CONTEXT, * LPWOW64CONTEXT;

//===============================================================================================//

DWORD inject_via_apcthread(HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress );

DWORD inject_via_remotethread(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress );

BOOL inject_dll( DWORD dwPid, DWORD pidArch, LPVOID lpBuffer, DWORD dwLength );

DWORD dll_inject_load( DWORD dwPid );

//===============================================================================================//
#endif
//===============================================================================================//