/////////////////////////////////////////////////////////////////////////////
////////////////////////////// API Hooker ///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

#include <Windows.h>
#include <stdarg.h>
#include <map>
#include <Strsafe.h>
using namespace std;
#include "NCodeHook.cpp"
#include "signatures.h"
#include "slre.h"
#include "wslre.h"
#include "apihook.h"
#include "reporting.h"
#include "base_inject.h"

////////////////////////////// Globals //////////////////////////////////////

//Our DLL-wide hooker, per-arch
#ifdef _M_X64
NCodeHook<ArchitectureX64> *hooker;
#else
NCodeHook<ArchitectureIA32> *hooker;
#endif

HMODULE myDllHandle; //my DLL base
map<void*, wslre*> compiledSignatures; //for regex signatures
PWCHAR procBlacklist; //global process blacklist
char* reportPipe;

//Stores a TLS slot # for our boolean to determine whether to enable alerts
DWORD enableAlertsSlot;

//Function to get the original function and signature passed to hook0
hookArgFunc getHookArg = NULL;
//Helper function to return a value from a hook, used with stackFixups
OneArgFunc setEax = NULL;
//Helper function to get a pointer to the PEB
NoArgFunc getPEB = NULL;
//For hooking new DLL loads
LdrLoadDllHookFunc realLdrLoadDll = NULL;

//For allocating RWX memory,
HANDLE rwxHeap = NULL;
//For allocating RW memory
HANDLE rwHeap = NULL;
//Configuration
HOOKAPI_CONF * apiConf = NULL;
//Stack fixup code chunks for returning from STDCALL
#define NUM_STACK_FIXUPS 30
NoArgFunc stackFixups[NUM_STACK_FIXUPS];
//Special stack fixups for the loadlib calls
PBYTE popRet1arg, popRet3arg;
//Keeps track of how many and what DLLs we have already hooked
HMODULE* dllHandles = NULL;
unsigned int dllHandlesHooked = 0;
//Calls a generic STDAPI function and returns the result
ThreeArgFunc callApi = NULL;

////////////////////////////// Runtime Functions //////////////////////////////////////

//Does the memory at address match the given memory protection constraints?
inline bool memCompareProtect(void* address, unsigned int mode, unsigned int type){
	if(mode == 0 && type == 0) // all zeroes - shortcut for no comparison
		return true;
	MEMORY_BASIC_INFORMATION mbi;
	if(VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
		return true; //Error. default true
	switch(type){
	case ANY:
		return (mbi.Protect & mode) != 0;
	case ALL:
		return (mbi.Protect & mode) == mode;
	case ONE: //aka EXACT
		return mbi.Protect == mode;
	case NONE:
		return (mbi.Protect & mode) == 0;
	}
	return true;
}

// Ensure we have compiled this regex
template<typename T, typename C>
void ensureSlreCompiled(C* arg, int (*compile)(T*,const C*)){
	if(compiledSignatures.count(arg) == 0){
		T* regex = (T*)HeapAlloc(rwHeap, HEAP_ZERO_MEMORY, sizeof(T));
		compiledSignatures[arg] = (wslre*)regex;
		if(regex != NULL)
			compile(regex, arg);
	}
}

//Evaluate each argument in a condition
inline bool argumentsMatch(HOOKAPI_ACTION_CONF* action, void** calledArgs){
	HOOKAPI_ARG_CONF* arg = actionConfArgs(action);
	for(unsigned int k = 0; k < action->numArgs; k++){
		void* calledArg = calledArgs[k];
		switch(arg->type){
		case DONTCARE:
			break;
		case DWORD_NEQ:
			if((size_t)(arg->value[0]) == (size_t)calledArg)
				return false;
			break;
		case DWORD_HOOK:
			if((size_t)(arg->value[0]) != (size_t)calledArg)
				return false;
			break;
		case DWORDRANGE:
			{
			bool belowLbound = (size_t)calledArg < (size_t)(arg->value[0]);
			bool aboveHbound = (size_t)calledArg > (size_t)(arg->value[1]);
			bool interiorRange = (size_t)(arg->value[0]) <= (size_t)(arg->value[1]);
			//e.g. range is 16 to 32
			if( ((belowLbound || aboveHbound) &&  interiorRange) ||
			//e.g. range is -16 to 16, interpreted here as Lbound 0xFFFFFFF0 Hbound 0x10 
			//so non-matches are < Lbound AND > Hbound
				((belowLbound && aboveHbound) && !interiorRange) )
				return false;
				break;
			}
		case CSTRING:
			{
				HOOKAPI_CSTRING_ARG* stringArg = (HOOKAPI_CSTRING_ARG*)arg->value;
				if(calledArg == NULL)
					return stringArg->value == 0; //Only empty strings match null
				ensureSlreCompiled<slre,char>(&stringArg->value, slre_compile);
				if(slre_match((slre*)compiledSignatures[&stringArg->value], (char*)calledArg, lstrlenA((char*)calledArg), NULL) == 0)
					return false;
				break;
			}
		case WCSTRING:
			{
				HOOKAPI_WCSTRING_ARG* stringArg = (HOOKAPI_WCSTRING_ARG*)arg->value;
				if(calledArg == NULL)
					return stringArg->value == 0; //Only empty strings match null
				ensureSlreCompiled<wslre,wchar_t>(&stringArg->value, wslre_compile);
				if(wslre_match(compiledSignatures[&stringArg->value], (wchar_t*)calledArg, lstrlenW((wchar_t*)calledArg), NULL) == 0)
					return false;
				break;
			}
		case MEM:
			{
				PHOOKAPI_MEM_ARG memArg = (PHOOKAPI_MEM_ARG)arg->value;
				if(memCompareProtect(calledArg, memArg->memMode, memArg->memType) == false)
					return false;
				break;
			}
		case BITMASK:
			{
				PHOOKAPI_BITMASK_ARG maskArg = (PHOOKAPI_BITMASK_ARG)arg->value;
				switch(maskArg->maskType){
				case ANY:
					if(((size_t)calledArg & maskArg->mask) == 0)
						return false;
					break;
				case ALL:
					if(((size_t)calledArg & maskArg->mask) != maskArg->mask)
						return false;
					break;
				case ONE: //aka EXACT
					if((size_t)calledArg != maskArg->mask)
						return false;
					break;
				case NONE:
					if(((size_t)calledArg & maskArg->mask) != 0)
						return false;
				}
			}
			break;
		case BLOB_HOOK:
			{
				HOOKAPI_BLOB_ARG* blobArg = (HOOKAPI_BLOB_ARG*)arg->value;
				if(calledArg == NULL)
					return blobArg->value == 0; //Only empty strings match null
				ensureSlreCompiled<slre,char>(&blobArg->value, slre_compile);
				size_t size = blobArg->size;
				if(blobArg->argument != -1)
					size = (size_t)calledArgs[blobArg->argument];
				if(size < INT_MAX && // we're not even going to try
					slre_match((slre*)compiledSignatures[&blobArg->value], (char*)calledArg, (int)size, NULL) != 1)
						return false;
			}
		}
		arg = nextArgConf(arg);
	}
	return true;
}

// Core logic of process and module black and white list comparisons
inline bool matchesModule(PWCHAR blacklist, PWCHAR whitelist, HMODULE mod){
	wchar_t fname[MAX_PATH];
	DWORD len = GetModuleFileNameW(mod, fname, sizeof(fname));
	if(len == 0)
		return true; // Not a module?! Default to matching.
	for (DWORD i = 0; i < len; i++)
		fname[i] = (wchar_t)tolower(fname[ i ]); // lower-case it!
	ensureSlreCompiled<wslre,wchar_t>(whitelist, wslre_compile);
	ensureSlreCompiled<wslre,wchar_t>(blacklist, wslre_compile);
	return (whitelist[0] == '\0' || wslre_match(compiledSignatures[whitelist], fname, len, NULL) == 1)
		&& (blacklist[0] == '\0' || wslre_match(compiledSignatures[blacklist], fname, len, NULL) == 0);
}

//Does the filename of the module including addr match the white/black lists?
inline bool moduleApplies(HOOKAPI_ACTION_CONF* action, PVOID addr){
	PWCHAR black = actionConfModBlack(action);
	PWCHAR white = actionConfModWhite(action);
	if((black[0] | white[0]) == '\0') // There is no condition, it matches
		return true;
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQuery(addr, &meminfo, sizeof(meminfo)); //Get module base from address
	return matchesModule(black, white, (HMODULE)meminfo.AllocationBase);
}

//Does this action apply to this process?
inline bool matchesProcess(HOOKAPI_ACTION_CONF* action){
	wchar_t* black = actionConfExeBlack(action);
	wchar_t* white = actionConfExeWhite(action);
	if((black[0] | white[0]) == '\0') // There is no condition, it matches
		return true;
	if(compiledSignatures.count(action) == 0){ // We haven't seen it before. Do the check.
		if(matchesModule(black, white, NULL))
			compiledSignatures[action] = PROC_MATCH;
		else
			compiledSignatures[action] = NO_PROC_MATCH;
	}
	return compiledSignatures[action] == PROC_MATCH;
}

// Evaluates all actions of a function, taking action if necessary
bool actionsBlock(HOOKAPI_FUNC_CONF* conf, void** calledArgs, DWORD type, void** retval){
	__try{
	HOOKAPI_ACTION_CONF* action = functionConfActions(conf);
	for(unsigned int i = 0; i < conf->numActions; i++){
		if(action->type == type // Is this a pre or post check?
				&& matchesProcess(action) == true // Should check this process?
				// Does it match our return address constraints?
				&& memCompareProtect(*(calledArgs - 1), action->retAddrMemMode, action->retAddrMemType)
				&& moduleApplies(action, *(calledArgs - 1)) //Should we check this module?
				&& argumentsMatch(action, calledArgs)){ //Do our argument conditions match?
			sendAlert(conf, action, calledArgs);
			//Take action!
			switch(action->action){
				case ALERT:
					break;
				case BLOCK:
					*retval = (void*)action->retval;
					return true;
				case KILLPROC:
					TerminateProcess(GetCurrentProcess(),ERROR_ACCESS_DENIED); //More forceful than ExitProcess()
				case KILLTHREAD:
					TerminateThread(GetCurrentThread(),ERROR_ACCESS_DENIED); //More forceful than ExitThread()
			}
		}
		//Next action
		action = nextActionConf(action);
	}
	}__except(exceptionFilter(GetExceptionInformation())){ //On exception - don't take action.
	}
	return false;
}

//This is the final hook that gets called for any function. It loads the function configuration
//and called arguments and takes any actions whose conditions match the corresponding signatures
//The 64 bit version has to initialize args so they are on the stack.
#ifdef _M_X64
void* hook0 (void* arg0, void* arg1, void* arg2, void* arg3){
	void** hookArgs = (*getHookArg)(); // opcode magic to get the hook arg pointer
	void** calledArgs = &arg0; // thanks to x64 convention, these will (sorta) be in order
	 //Ensure the other args actually written to the stack too
	calledArgs[1] = arg1;
	calledArgs[2] = arg2;
	calledArgs[3] = arg3;
#else
void* hook0 (void* arg0){
	void** hookArgs = (*getHookArg)(); // opcode magic to get the hook arg pointer
	void** calledArgs = &arg0; // thanks to STDCALL convention, these will be in order
#endif
	HOOKAPI_FUNC_CONF* conf = (HOOKAPI_FUNC_CONF*)hookArgs[0]; //get configuration
	NoArgFunc retfunc = stackFixups[conf->numArgs];

	if(!alertsEnabled()){ // If alerts are disabled, ignore configuration
		setEax(callApi(&arg0, (void*)conf->numArgs, hookArgs[1]));
		return retfunc();
	}

	void* retval;
	//Check PRE actions before call and if not blocked...
	if(!actionsBlock(conf, calledArgs, PRE, &retval)){
		retval = callApi(&arg0, (void*)conf->numArgs, hookArgs[1]); //call the real function
		DWORD originalLastError = GetLastError();
		actionsBlock(conf, calledArgs, POST, &retval); //and check POST actions afterward
		SetLastError(originalLastError);
	}

	setEax(retval);  //And return the result
	return retfunc();
}

//CreateProcessInternalW hook functionality - ensures new processes get DLL loaded
typedef DWORD (WINAPI * CreateProcessInternalWFunc)( PVOID, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, 
	LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION,PVOID);
CreateProcessInternalWFunc CreateProcessInternalWReal;
DWORD WINAPI CreateProcessInternalWHook(PVOID token, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PVOID newToken){
	bool alreadySuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
	DWORD retval = CreateProcessInternalWReal(token, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, 
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, newToken);
	DWORD originalLastError = GetLastError();

	// If something weird or broken is happening, don't continue
	size_t applen = (size_t)-1;
	if(lpApplicationName != 0)
		applen = lstrlenW(lpApplicationName);
	if(retval == 0 || (dwCreationFlags  & (CREATE_PROTECTED_PROCESS)) != 0 || newToken != 0
			//Or the process is blacklisted
			|| (applen != (size_t)-1 && applen < INT_MAX && procBlacklist[0] != '\0' 
				&& wslre_match(compiledSignatures[procBlacklist], lpApplicationName, (int)applen, NULL))){
		if(!alreadySuspended)
			ResumeThread(lpProcessInformation->hThread);
		//Log error and reason
		WCHAR errorinfo[300];
		errorinfo[0] = 0;
		StringCbPrintfExW(errorinfo, sizeof(errorinfo), NULL, NULL, STRSAFE_IGNORE_NULLS,
				L"CreateProcessInternalWHook abort - retval %d creation flags %p token %p nt %p appname %s cmdline %s",
				retval, dwCreationFlags, token, newToken, lpApplicationName, lpCommandLine);
		reportError(errorinfo);
		SetLastError(originalLastError);
		return retval;
	}

	disableAlerts();
	dll_inject_load(lpProcessInformation->hProcess, lpProcessInformation->hThread); // Try msf-style cross-arch inject
	if(!alreadySuspended)
		ResumeThread(lpProcessInformation->hThread);
	enableAlerts();
	SetLastError(originalLastError);
	return retval;
}

//Hook for ntdll!LdrLoadDll - ensures newly loaded libraries are hooked
NTSTATUS NTAPI LdrLoadDllHook(PWCHAR PathToFile, PVOID Flags, PVOID ModuleFileName, PHANDLE ModuleHandle){
	NTSTATUS result = 0;
	__try{
		result = realLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
		DWORD originalLastError = GetLastError();
		if(ModuleHandle != NULL && *ModuleHandle != NULL)
			hookDllApi((HMODULE)*ModuleHandle);
		SetLastError(originalLastError);
	}__except(exceptionFilter(GetExceptionInformation())){ //On exception - don't take action.
	}
	return result;
}

////////////////////////////// Setup Functions //////////////////////////////////////

//Makes a hook of an arbitrary function that calls hook0 with a given argument using a springboard
bool makeHook(void* origProcAddr, void* farg, void* hook){
	if(origProcAddr == NULL)
		return false;
	//args = [arg, origFunc]
	void** args = (void**)HeapAlloc(rwHeap, 0, sizeof(void*)*2);
	if(args == NULL)
		return false;
	args[0] = farg;

	//Now make springboard
	HOOKAPI_SPRINGBOARD* springboard = getSpringboard(args, hook, rwxHeap);
	if(springboard == NULL)
		return false;
	return hooker->createHook<NoArgFunc>((NoArgFunc)origProcAddr, (NoArgFunc)springboard, (NoArgFunc *)&(args[1]));
}

//Prepares some memory items we'll need before calling makeHook on an arbitrary function
//and loads configuration into memory. THIS IS RUN IN DLLMAIN AND CANNOT LOAD LIBRARIES!
bool prepHookApi(){
	//Get rw heap
	rwHeap = GetProcessHeap();
	if(rwHeap == NULL)
		return false;

	//Find configuration file from same binary directory as this file
	char filename[1000];
	DWORD size = GetModuleFileNameA(myDllHandle, filename, sizeof(filename));
	for(size -= 1; filename[size] != '\\' && size != 0; size--)
		filename[size] = 0;
	strcat_s(filename, "sig.dat"); // yes, I know this is VS-specific

	//Read configuration file
	HANDLE sigFileHandle = CreateFileA(filename,GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,0);
	DWORD dontcare;
	DWORD fileSize = GetFileSize(sigFileHandle,NULL);
	if(fileSize == -1 || sigFileHandle == INVALID_HANDLE_VALUE ||
			(apiConf = (HOOKAPI_CONF*)HeapAlloc(rwHeap,0,fileSize)) == NULL ||
			ReadFile(sigFileHandle,apiConf,fileSize,&dontcare,NULL) == FALSE){
		CloseHandle(sigFileHandle);
		reportError(L"Could not read configuration file");
		return false;
	}
	CloseHandle(sigFileHandle);

	//If this signature is a different version than we were built for, don't go.
	if(apiConf->version != HOOKAPI_SIG_VERSION){
		HeapFree(rwHeap,0,apiConf);
		reportError(L"Invalid signature version");
		return false;
	}

	//If there is a blacklist, and it excludes us, abort before we hook anything
	procBlacklist = apiConfProcBlacklist(apiConf);
	if(procBlacklist[0] != 0 && !matchesModule(procBlacklist, L"", NULL)){
		HeapFree(rwHeap,0,apiConf);
		return false;
	}

	//We're good to load - make an RWX heap and setup TLS alert enable/disable 
	setupAlertsDisabled();
	rwxHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE,0,0);

	//Our DLL-wide hooker, per-arch
	#ifdef _M_X64
	hooker = new NCodeHook<ArchitectureX64> (rwxHeap);
	#else
	hooker = new NCodeHook<ArchitectureIA32>(rwxHeap);
	#endif
	dllHandles = (HMODULE*)HeapAlloc(rwHeap, 0, 32 * sizeof(HMODULE));
	if(dllHandles == NULL) //no memory. c'mon!
		return false;

	//Setup getHookArg(), setEax(), getPEB(), and callApi()
	getHookArg = (hookArgFunc)HeapAlloc(rwxHeap, 0, sizeof(GET_HOOK_ARG));
	setEax = (OneArgFunc)HeapAlloc(rwxHeap, 0, sizeof(SET_EAX));
	getPEB = (NoArgFunc)HeapAlloc(rwxHeap, 0, sizeof(GET_PEB));
	callApi = (ThreeArgFunc)HeapAlloc(rwxHeap, 0, sizeof(CALL_API));
	if(getHookArg == NULL || setEax == NULL || getPEB == NULL || callApi == NULL)
		return false; //no memory. c'mon! This really shouldn't happen with a new heap
	MoveMemory((PCHAR)getHookArg, GET_HOOK_ARG, sizeof(GET_HOOK_ARG)); 
	MoveMemory((PCHAR)setEax, SET_EAX, sizeof(SET_EAX));
	MoveMemory((PCHAR)getPEB, GET_PEB, sizeof(GET_PEB));
	MoveMemory((PCHAR)callApi, CALL_API, sizeof(CALL_API));

	//Setup stack fixups for returning
	for(WORD i = 0; i < NUM_STACK_FIXUPS; i++){
		stackFixups[i] = (NoArgFunc)HeapAlloc(rwxHeap, 0, sizeof(STACK_FIXUP) + 2);
		if(stackFixups[i] == NULL)
			return false; //no memory.
		MoveMemory(stackFixups[i], STACK_FIXUP, sizeof(STACK_FIXUP));
		*((PWORD)((PBYTE)stackFixups[i] + sizeof(STACK_FIXUP) - 1)) = i * sizeof(void*); // sets the return value
	}

	FARPROC cpiw = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateProcessInternalW");
	if(cpiw == NULL)
		cpiw = GetProcAddress(GetModuleHandleA("kernel32"), "CreateProcessInternalW");

	//Hook CreateProcessInternal calls to ensure apihook is loaded into new processes
	hooker->createHook<CreateProcessInternalWFunc>((CreateProcessInternalWFunc)cpiw, 
		(CreateProcessInternalWFunc)CreateProcessInternalWHook, &CreateProcessInternalWReal);

	//Setup LdrLoadDll to ensure signatures are loaded on dynamically-loaded DLLs
	hooker->createHook<LdrLoadDllHookFunc>((LdrLoadDllHookFunc)
		GetProcAddress(GetModuleHandleA("ntdll"),"LdrLoadDll"), LdrLoadDllHook, &realLdrLoadDll);
	return true;
}

//This function loads up hooks for a DLL if it has not been hooked before
bool hookDllApi(HMODULE dllHandle){
	//Check if valid
	if(dllHandle == NULL)
		return false;

	//Check if we've seen it already
	for(size_t i = 0; i < dllHandlesHooked; i++)
		if(dllHandles[i] == dllHandle)
			return true;
	if(dllHandlesHooked != 0 && (dllHandlesHooked % 32) == 0)  //Out of mem - realloc
		dllHandles = (HMODULE*)HeapReAlloc(rwHeap, 0, dllHandles, (dllHandlesHooked + 32) * sizeof(HMODULE));
	dllHandles[dllHandlesHooked++] = dllHandle;

	//Get DLL name
	char filename[MAX_PATH+1];
	if(GetModuleFileNameA(dllHandle, filename, sizeof(filename)) == 0)
		return false; //uhoh - not a DLL?
	const char* name = strrchr(filename,'\\') + 1;

	//Find DLL conf
	HOOKAPI_DLL_CONF* dllConf = apiConfDlls(apiConf);
	bool found = false;
	for(unsigned int i = 0; i < apiConf->numdlls; i++){
		if(_stricmp(dllConf->name,name) == 0){
			found = true;
			break;
		}
		dllConf = nextDllConf(dllConf); // next
	}
	if(found == false)
		return false;

	//Don't allow alerts here
	disableAlerts();

	//Hook each function conf
	HOOKAPI_FUNC_CONF* function = dllConfFunctions(dllConf);
	for(unsigned int i = 0; i < dllConf->numFunctions; i++){
		bool valid = false;
		HOOKAPI_ACTION_CONF* action = functionConfActions(function);
		for(unsigned int i = 0; i < function->numActions; i++){
			if(matchesProcess(action)){
				valid = true;
				break;
			}
			action = nextActionConf(action);
		}
		if(valid)
			makeHook(GetProcAddress(dllHandle, function->name), function, &hook0);
		function = nextFunctionConf(function); //next
	}
	enableAlerts(); //back to normal
	return true;
}

//Hook all loaded DLL's
bool hookAllDlls(){
	PPEB peb = (PPEB)getPEB(); // Get PEB
	//Walk module list and call hookDllApi for all
	PLIST_ENTRY moduleListHead = &peb->Ldr->InMemoryOrderModuleList;
	for(PLIST_ENTRY entry = moduleListHead->Flink;
		entry != NULL && entry != moduleListHead; entry = entry->Flink)
		hookDllApi((HMODULE)((PLDR_DATA_TABLE_ENTRY)(entry - 1))->DllBase);
	return true;
}
//Post-DllMain-init. Doesn't really take an arg, just for CreateThread
DWORD WINAPI postInit(PVOID){
	hookAllDlls(); //Hook the ones we have now
	return checkLogging(); //Setup a log server for this system or just check in
}

//And this is our main function
BOOL WINAPI DllMain(HINSTANCE instance, DWORD fdwReason, LPVOID){
	if(fdwReason == DLL_THREAD_ATTACH)
		enableAlerts();
	if(fdwReason != DLL_PROCESS_ATTACH)
		return TRUE;
	myDllHandle = instance;
	if(prepHookApi() == false)
		return TRUE; //not really, but we want to exit without raising alarms

	hookAllDlls(); //Hook the ones we have now
	//And check again after all dlls are initialized
	CreateThread(NULL, 0, &postInit, NULL, 0, NULL); //This will run after all DllMains
	enableAlerts();
	return TRUE;
}
