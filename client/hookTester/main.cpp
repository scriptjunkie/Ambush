#include <windows.h>
#include <cstring>
#include <ctime>
#include <psapi.h>

bool quiet = false;
bool thread = false;
typedef HANDLE (WINAPI *URLDownloadToFileWFunc)(
    LPUNKNOWN pCaller,
    LPCWSTR szURL,
    LPCWSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
);
typedef int (WINAPI * recvfunc)(int s, char *buf, int len, int flags);
DWORD WINAPI ThreadProc(LPVOID arg){
	thread = true;
	if(!quiet)
		MessageBoxA(NULL,"I am in a new thread!","Ambush tester",0);
	return 0;
}
bool ask(const char* message){
	return quiet || MessageBoxA(NULL, message, "Ambush tester", MB_YESNO) == IDYES;
}
void error(const char* message){
	if(quiet)
		MessageBoxA(NULL, message, "ERROR - Ambush test", MB_ICONERROR);
}
int CALLBACK WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
	quiet = strstr(GetCommandLineA(), "quiet") != NULL;

	//Change directory to binary directory
	char filename[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, filename, sizeof(filename));
	for(size -= 1; filename[size] != '\\' && size != 0; size--)
		filename[size] = 0;
	SetCurrentDirectoryA(filename);

	if(ask("Update signatures?"))
		system("config.exe update");

	if(ask("Manually load library?"))
#ifdef _M_X64
		if(LoadLibraryA("apihook64.dll") == NULL)
#else
		if(LoadLibraryA("apihook.dll") == NULL)
#endif
			MessageBoxA(NULL,"Load failed!","Hook Tester",0);

	//ALLOW TEST
	clock_t one=clock();
	if(ask("Test starting. SleepEx 1000..."))
		SleepEx(1000, FALSE);
	if(quiet && clock() - one < CLOCKS_PER_SEC / 2)
		error("SleepEx(1000, 0) exited early");

	//BLOCK AND AGGREGATION TEST
	one=clock();
	if(ask("SleepEx 1001 quad"))
		for(int i = 0; i < 4; i++)
			SleepEx(1001, FALSE);
	if(ask("SleepEx 1001 quad"))
		for(int i = 0; i < 4; i++)
			SleepEx(1001, FALSE);
	if(quiet && clock() - one > CLOCKS_PER_SEC * 5)
		error("SleepEx(1001, 0) was not blocked");

	//URLDOWNLOADTOFILEW TEST
	//Test LoadLibrary, GetProcAddress, WC string regex
	DeleteFileA("deleteme.txt");
	URLDownloadToFileWFunc URLDownloadToFileW = (URLDownloadToFileWFunc)
		GetProcAddress(LoadLibraryA("urlmon"), "URLDownloadToFileW");
	if(ask("URLDownloadToFileW http://www.yahoo.com/"))
		if(URLDownloadToFileW(NULL, L"http://www.yahoo.com/", L"deleteme.txt", 0, NULL) != (HANDLE)73)
			error("URLDOWNLOADTOFILEW wrong return value");

	//RECV TEST
	//Test LoadLibrary, GetProcAddress, Pointer, and Integer range
	recvfunc myrecv = (recvfunc)GetProcAddress(LoadLibraryA("ws2_32.dll"), "recv");
	PVOID rwx = VirtualAlloc(NULL, 1021, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(ask("winsock recv"))
		if(myrecv(0, (char*)rwx, 1021, 0) != 0)
			error("Ws2_32 recv did not return the correct value");

	//INJECT TEST - ensures library is loaded into all new processes
	STARTUPINFOA start;
	PROCESS_INFORMATION proc;
	memset(&start,0,sizeof(start));
	memset(&proc,0,sizeof(proc));
	start.cb = sizeof(start);
	char cmdline[100];
	lstrcpyA(cmdline,"cmd.exe");
	if(ask("Start cmd")){
		CreateProcessA(NULL,cmdline,NULL,NULL,0,0,NULL,NULL,&start,&proc);
		HMODULE hmods[100];
		DWORD bytes = sizeof(hmods);
		CHAR modname[MAX_PATH];
		bool found = false;
		if(EnumProcessModules(proc.hProcess, hmods, sizeof(hmods), &bytes))
			for(int i = 0; i < (bytes / sizeof(HMODULE)); i++)
				if(GetModuleFileNameExA(proc.hProcess, hmods[i], modname, MAX_PATH))
					if(strstr(modname, "apihook") != NULL)
						found = true;
		if(found == false)
			error("Process injection failed!");
		TerminateProcess(proc.hProcess, 0);
	}

	//TEST NOT
	if(ask("Non-remote CreateRemoteThread")){
		WaitForSingleObject(CreateRemoteThread(GetCurrentProcess(),NULL,0,&ThreadProc,NULL,0,NULL), 500);
		if(thread != true)
			error("Thread did not run!");
	}

	//Test killproc with sleepEx 1002
	if(ask("Read PE")){
		GetModuleFileNameA(NULL, filename, sizeof(filename));
		HANDLE h = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, 
			NULL, OPEN_EXISTING, NULL, NULL);
		char readbuf[1000];
		DWORD dontcare;
		ReadFile(h,readbuf,sizeof(readbuf),&dontcare,NULL);
		CloseHandle(h);
	}
	error("Read PE Kill process failed!");
}
