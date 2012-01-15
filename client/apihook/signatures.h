#pragma once

enum ArgType { DONTCARE, DWORD_HOOK, DWORDRANGE, CSTRING, WCSTRING, MEM, BITMASK, BLOB_HOOK, DWORD_NEQ };

#pragma pack(push,4)
typedef struct sHOOKAPI_BLOB_ARG
{
    unsigned int   argument;
    unsigned int   size;
    unsigned int   valSize;
    char   value;
} HOOKAPI_BLOB_ARG, *PHOOKAPI_BLOB_ARG;

typedef struct sHOOKAPI_CSTRING_ARG
{
    unsigned int   size;
    char   value;
} HOOKAPI_CSTRING_ARG, *PHOOKAPI_CSTRING_ARG;

typedef struct sHOOKAPI_WCSTRING_ARG
{
    unsigned int   size;
    wchar_t   value;
} HOOKAPI_WCSTRING_ARG, *PHOOKAPI_WCSTRING_ARG;

typedef struct sHOOKAPI_BITMASK_ARG
{
    unsigned int   maskType;
    unsigned long long   mask;
} HOOKAPI_BITMASK_ARG, *PHOOKAPI_BITMASK_ARG;

typedef struct sHOOKAPI_MEM_ARG
{
    unsigned int   memType;
    unsigned int   memMode;
} HOOKAPI_MEM_ARG, *PHOOKAPI_MEM_ARG;

typedef struct sHOOKAPI_ARG_CONF
{
    unsigned int   size;
    unsigned int   type;
    unsigned long long   value[1];
} HOOKAPI_ARG_CONF, *PHOOKAPI_ARG_CONF;
inline PHOOKAPI_ARG_CONF nextArgConf(PHOOKAPI_ARG_CONF conf){
	return (PHOOKAPI_ARG_CONF) ((PBYTE)conf + conf->size);
}

enum ActionType { PRE, POST };

enum BitmaskMode { ANY, ALL, ONE, NONE };

typedef struct sHOOKAPI_ACTION_CONF
{
    unsigned int   size;
    unsigned int   id;
    unsigned int   action;
    unsigned int   severity;
    unsigned long long   retval;
    unsigned int   type;
    unsigned int   numArgs;
    unsigned int   exePathLen;
    unsigned int   retAddrMemType;
    unsigned int   retAddrMemMode;
	char exePath[1];
	//HOOKAPI_CONDITION_CONF conditions[1];
} HOOKAPI_ACTION_CONF, *PHOOKAPI_ACTION_CONF;

//Get Functions
inline PHOOKAPI_ARG_CONF actionConfArgs(PHOOKAPI_ACTION_CONF conf){
	return (PHOOKAPI_ARG_CONF) ((PBYTE)conf + sizeof(unsigned int) * 9 +
		sizeof(unsigned long long) + conf->exePathLen);
}
inline PHOOKAPI_ACTION_CONF nextActionConf(PHOOKAPI_ACTION_CONF conf){
	return (PHOOKAPI_ACTION_CONF) ((PBYTE)conf + conf->size);
}

//Actions
enum HookAction { ALERT, BLOCK, KILLPROC, KILLTHREAD };

#define START_INFO (DWORD)-1

typedef struct sHOOKAPI_FUNC_CONF
{
    unsigned int   size;
    unsigned int   numArgs;
    unsigned int   numActions;
    unsigned int   nameLen;
	char name[1];
	//HOOKAPI_ACTION_CONF actions[1];
} HOOKAPI_FUNC_CONF, *PHOOKAPI_FUNC_CONF;

//Get Functions
inline PHOOKAPI_ACTION_CONF functionConfActions(PHOOKAPI_FUNC_CONF conf){
	return (PHOOKAPI_ACTION_CONF) ((PBYTE)conf + sizeof(unsigned int) * 4 + conf->nameLen);
}
inline PHOOKAPI_ARG_CONF functionConfParameters(PHOOKAPI_FUNC_CONF conf){
	PHOOKAPI_ACTION_CONF actions = functionConfActions(conf);
	for(unsigned int i = 0; i < conf->numActions; i++)
		actions = nextActionConf(actions);
	return (PHOOKAPI_ARG_CONF) actions;
}
inline PHOOKAPI_FUNC_CONF nextFunctionConf(PHOOKAPI_FUNC_CONF conf){
	return (PHOOKAPI_FUNC_CONF) ((PBYTE)conf + conf->size);
}

typedef struct sHOOKAPI_DLL_CONF
{
    unsigned int   size;
    unsigned int   numFunctions;
    unsigned int   nameLen;
	char name[1];
	//HOOKAPI_FUNC_CONF functions[1];
} HOOKAPI_DLL_CONF, *PHOOKAPI_DLL_CONF;

//Get Functions
inline PHOOKAPI_FUNC_CONF dllConfFunctions(PHOOKAPI_DLL_CONF conf){
	return (PHOOKAPI_FUNC_CONF) ((PBYTE)conf + sizeof(unsigned int) * 3 + conf->nameLen);
}
inline PHOOKAPI_DLL_CONF nextDllConf(PHOOKAPI_DLL_CONF conf){
	return (PHOOKAPI_DLL_CONF) ((PBYTE)conf + conf->size);
}

typedef struct sHOOKAPI_CONF
{
    unsigned int   version;
    unsigned int   serial;
    unsigned int   numdlls;
	unsigned int   reportServerLen;
	char           reportServer[1];
	//HOOKAPI_DLL_CONF dlls[1];
} HOOKAPI_CONF, *PHOOKAPI_CONF;

//Get DLLs
inline PHOOKAPI_DLL_CONF apiConfDlls(PHOOKAPI_CONF conf){
	return (PHOOKAPI_DLL_CONF) ((PBYTE)conf + sizeof(unsigned int) * 4 + conf->reportServerLen);
}

#pragma pack(pop)
