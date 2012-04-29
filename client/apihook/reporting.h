#pragma once
#include "apihook.h"

//default max 100mb log file size
#define LOG_FILE_SIZE_LIMIT 100000000

typedef struct myAlertQueueNode {
	PHOOKAPI_MESSAGE message;
	HANDLE eventHandle;
    myAlertQueueNode * next;
} AlertQueueNode;

BOOL checkLogging();
void sendAlert(HOOKAPI_FUNC_CONF* conf, HOOKAPI_ACTION_CONF* action, void** calledArgPtr);

//exception reporting
DWORD exceptionFilter(LPEXCEPTION_POINTERS pointers);
BOOL reportError(PWCHAR errorStr);
