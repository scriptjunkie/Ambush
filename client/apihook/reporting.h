#pragma once
#include "apihook.h"

typedef struct myAlertQueueNode {
	PHOOKAPI_MESSAGE message;
	HANDLE eventHandle;
    myAlertQueueNode * next;
} AlertQueueNode;

BOOL checkLogging();
void sendAlert(HOOKAPI_FUNC_CONF* conf, HOOKAPI_ACTION_CONF* action, void** calledArgPtr);
