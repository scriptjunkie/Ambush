#include <windows.h>
#include <winhttp.h>
#include <sddl.h>
#include <aclapi.h>
#include <Lmcons.h>
#include <string>
using namespace std;

#include "reporting.h"
#include "signatures.h"
#include "apihook.h"

//Default 20s to conglomerate alerts
#define ALERT_INTERVAL 20000
#define SERVER_PORT 3000

// some winHTTP defines
HINTERNET (WINAPI *mWinHttpOpen)(
  __in_opt  LPCWSTR pwszUserAgent,
  __in      DWORD dwAccessType,
  __in      LPCWSTR pwszProxyName,
  __in      LPCWSTR pwszProxyBypass,
  __in      DWORD dwFlags
);
HINTERNET (WINAPI *mWinHttpConnect)(
  __in        HINTERNET hSession,
  __in        LPCWSTR pswzServerName,
  __in        INTERNET_PORT nServerPort,
  __reserved  DWORD dwReserved
);
HINTERNET (WINAPI *mWinHttpOpenRequest)(
  __in  HINTERNET hConnect,
  __in  LPCWSTR pwszVerb,
  __in  LPCWSTR pwszObjectName,
  __in  LPCWSTR pwszVersion,
  __in  LPCWSTR pwszReferrer,
  __in  LPCWSTR *ppwszAcceptTypes,
  __in  DWORD dwFlags
);
BOOL (WINAPI *mWinHttpSendRequest)(
  __in      HINTERNET hRequest,
  __in_opt  LPCWSTR pwszHeaders,
  __in      DWORD dwHeadersLength,
  __in_opt  LPVOID lpOptional,
  __in      DWORD dwOptionalLength,
  __in      DWORD dwTotalLength,
  __in      DWORD_PTR dwContext
);
BOOL (WINAPI *mWinHttpReceiveResponse)(
  __in        HINTERNET hRequest,
  __reserved  LPVOID lpReserved
);
BOOL (WINAPI *mWinHttpReadData)(
  __in   HINTERNET hRequest,
  __out  LPVOID lpBuffer,
  __in   DWORD dwNumberOfBytesToRead,
  __out  LPDWORD lpdwNumberOfBytesRead
);
BOOL (WINAPI *mWinHttpCloseHandle)(
  __in  HINTERNET hInternet
);
PWCHAR computerName = NULL;
DWORD computerNameLen = 0;
WCHAR exeFileName[MAX_PATH];
DWORD exeNameLen = 0;

//Loads the winhttp dll and links up all our functions
BOOL loadWinHTTP(){
	HMODULE winhttpdll = LoadLibraryA("Winhttp.dll");
	mWinHttpOpen = (HINTERNET (WINAPI *)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD))
		GetProcAddress(winhttpdll,"WinHttpOpen");
	mWinHttpConnect = (HINTERNET (WINAPI *)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD))
		GetProcAddress(winhttpdll,"WinHttpConnect");
	mWinHttpOpenRequest = (HINTERNET (WINAPI *)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD))
		GetProcAddress(winhttpdll,"WinHttpOpenRequest");
	mWinHttpSendRequest = (BOOL (WINAPI *)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR))
		GetProcAddress(winhttpdll,"WinHttpSendRequest");
	mWinHttpReceiveResponse = (BOOL (WINAPI *)(HINTERNET,LPVOID))
		GetProcAddress(winhttpdll,"WinHttpReceiveResponse");
	mWinHttpReadData = (BOOL (WINAPI *)(HINTERNET,LPVOID,DWORD,LPDWORD))
		GetProcAddress(winhttpdll,"WinHttpReadData");
	mWinHttpCloseHandle = (BOOL (WINAPI *)(HINTERNET))
		GetProcAddress(winhttpdll,"WinHttpCloseHandle");
	return mWinHttpCloseHandle != NULL && mWinHttpReadData != NULL && mWinHttpReceiveResponse != NULL
		&& mWinHttpSendRequest != NULL && mWinHttpOpenRequest != NULL 
		&& mWinHttpConnect != NULL && mWinHttpOpen != NULL;
}

//Checks into a listening local server - not ours
BOOL checkIn(){
	DWORD result = 0;
	DWORD cbRead;
	PWCHAR commandLine = GetCommandLineW();
	DWORD commandLineLen = lstrlenW(commandLine) * sizeof(WCHAR); //in bytes
	DWORD size = commandLineLen + sizeof(HOOKAPI_MESSAGE); //size of struct
	PHOOKAPI_MESSAGE message = (PHOOKAPI_MESSAGE)HeapAlloc(rwHeap, 0, size);
	if(message == NULL)
		return FALSE; // no memory. sad face.
	message->length = size;
	message->type = START_INFO;
	message->numArgs = 0;
	message->pid = GetCurrentProcessId();
	memcpy(((char*)message) + sizeof(HOOKAPI_MESSAGE), commandLine, commandLineLen);
	//Check in 
	CallNamedPipeA(LOCAL_REPORT_PIPE, message, message->length, &result, 
			sizeof(result), &cbRead, NMPWAIT_WAIT_FOREVER);
	HeapFree(rwHeap, 0, message);
	return TRUE;
}

//Endlessly polls queue for new alerts, sending them to the HTTP server
DWORD WINAPI HTTPthread(AlertQueueNode* argnode){
	// Alert handling - disable alerts to prevent recursion
	disableAlerts();

	// Use WinHttpOpen to obtain a session handle.
	if(loadWinHTTP() == FALSE)
		return FALSE;
	HINTERNET hConnect = NULL,
	hRequest = NULL,
	hSession = mWinHttpOpen(L"Ambush IPS Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	//Get reporting server
	size_t unused;
	WCHAR server[257];
	mbstowcs_s(&unused, server, apiConf->reportServer, apiConf->reportServerLen);

	//Get start time & queue head
	AlertQueueNode* lastnode = argnode;
	LARGE_INTEGER lastAlert, currentTime;
	DWORD msDifference;
	while(true){ //infinite loop
		//Wait for next alert
		WaitForSingleObject(lastnode->eventHandle, INFINITE);
		GetSystemTimeAsFileTime((LPFILETIME)&lastAlert);
		// arrays of unique alerts
		const int max_alerts = 32;
		PHOOKAPI_MESSAGE alerts[max_alerts];
		int alertCount = 0;
		do{ //Loop to get all alerts for up to 20 seconds
			AlertQueueNode* nextnode = lastnode->next;
			HeapFree(rwHeap, 0, lastnode); //throw away last
			lastnode = nextnode; //now last is the current one to be processed.
			PHOOKAPI_MESSAGE message = lastnode->message;

			//See if it is a dup
			bool dup = false;
			for(int i = 0; i < alertCount; i++){
				if(messageEqual(alerts[i], message)){ // it's a dup
					alerts[i]->count += message->count; // Add count
					dup = true;
					HeapFree(rwHeap, 0, message); //don't need this anymore
					break;
				}
			}
			if(dup == false){ //new alert, save a copy and check alert count
				alerts[alertCount] = message;
				alertCount++;
				if(alertCount == max_alerts)
					break; //We can't take any more!
			}
			GetSystemTimeAsFileTime((LPFILETIME)&currentTime); // must be reached on first loop pass
			msDifference = (DWORD)((currentTime.QuadPart - lastAlert.QuadPart) / 10000);
			if(msDifference > ALERT_INTERVAL) //20 seconds
				break;
		} while(WaitForSingleObject(lastnode->eventHandle, ALERT_INTERVAL - msDifference) == WAIT_OBJECT_0);
		lastAlert.QuadPart = currentTime.QuadPart;

		// Connect to the HTTP server.
		if (hSession)
			hConnect = mWinHttpConnect( hSession, server, SERVER_PORT, 0);//INTERNET_DEFAULT_HTTP_PORT
		//Send request for each alert
		for(int i = 0; i < alertCount; i++){
			// Create an HTTP Request handle.
			if (hConnect)
				hRequest = mWinHttpOpenRequest( hConnect, L"POST", L"/alerts", 
						NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,0);
			BOOL  bResults = FALSE;
			if (hRequest)
				bResults = mWinHttpSendRequest( hRequest, L"Content-Type: application/octet-stream\r\n",
						(DWORD)-1, alerts[i], alerts[i]->length, alerts[i]->length, 0);
			HeapFree(rwHeap, 0, alerts[i]);
			if (bResults)
				bResults = mWinHttpReceiveResponse( hRequest, NULL);
			//if (!bResults)...Errors. What do we do? Can't report to server. Already logged. oh well.
			if (hRequest) mWinHttpCloseHandle(hRequest);
		}
		if (hConnect) mWinHttpCloseHandle(hConnect);
	}
	if (hSession) mWinHttpCloseHandle(hSession); //not that we'll ever get here...
}

//Keep track of alerts on this system, log them to disk and report to server
BOOL runLocalServer(HANDLE servPipe){
	//Get output filename from same directory as this file
	char filename[1000];
	DWORD size = GetModuleFileNameA(myDllHandle, filename, sizeof(filename));
	for(size -= 1; filename[size] != '\\' && size != 0; size--)
		filename[size] = 0;
	strcat_s(filename, REPORT_FILE); // yes, I know this is VS-specific
	//Open the file
	HANDLE outputFile = CreateFileA(filename,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
	if(outputFile == INVALID_HANDLE_VALUE)
		return 0; //we can't store our messages!

	// Ok, we're good. Now disable alerts from this thread to prevent recursive alerts.
	disableAlerts();

	//Start winHTTP thread
	AlertQueueNode* baseNode = (AlertQueueNode*)HeapAlloc(rwHeap,HEAP_ZERO_MEMORY,sizeof(AlertQueueNode));
	if(baseNode == NULL)
		return 0; //Uhoh. no memory. we're screwed.
	baseNode->eventHandle = CreateEvent(NULL,TRUE,FALSE,NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HTTPthread, baseNode, 0, NULL);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST); // So we don't drop alerts
	PHOOKAPI_MESSAGE message;
	while(true){
		message = (PHOOKAPI_MESSAGE)HeapAlloc(rwHeap, 0, 2000);
		if(message == NULL){ //This has got to work. so just wait until it does
			Sleep(1000);
			continue;
		}
		DisconnectNamedPipe(servPipe); //just in case of previous error
		//Receive a message
		if(ConnectNamedPipe(servPipe, NULL) == FALSE && GetLastError() != ERROR_PIPE_CONNECTED){
			HeapFree(rwHeap, 0, message);
			continue; //Error
		}
		DWORD numBytes;
		if (!ReadFile( servPipe,  message,  2000, &numBytes, NULL) || numBytes == 0){
			HeapFree(rwHeap, 0, message);
			continue; //Error
		}
		if(numBytes < message->length){ //Go get more if we need it
			PHOOKAPI_MESSAGE oldmessage = message;
			message = (PHOOKAPI_MESSAGE)HeapAlloc(rwHeap, 0, message->length);
			if(message == NULL){
				HeapFree(rwHeap, 0, message);
				continue; //no memory. sad face.
			}
			memcpy(message, oldmessage, numBytes);
			HeapFree(rwHeap, 0, oldmessage);
			if (!ReadFile(servPipe, ((PBYTE)message) + numBytes, message->length - numBytes, 
				&numBytes, NULL) || numBytes == 0){
					HeapFree(rwHeap, 0, message);
					continue; //Error
			}
		}
		// Save to file
		FILETIME filetime;
		GetSystemTimeAsFileTime(&filetime); //save time
		DWORD written;
		if (!WriteFile(outputFile, &filetime, sizeof(filetime), &written, NULL) 
			|| !WriteFile(outputFile, message, message->length, &written, NULL)){ //save alert
			HeapFree(rwHeap, 0, message);
			continue; //Error
		}
		FlushFileBuffers(outputFile);

		//Don't send start infos to server
		if(message->type == START_INFO)
			continue;
		//Send rest to server
		PVOID nextNode = HeapAlloc(rwHeap,HEAP_ZERO_MEMORY,sizeof(AlertQueueNode));
		if(nextNode != NULL){ //ouch. we're probably screwed. But for right now, just ignore
			baseNode->next = (AlertQueueNode*)nextNode;
			AlertQueueNode* oldNode = baseNode;
			baseNode = baseNode->next;
			baseNode->eventHandle = CreateEvent(NULL,TRUE,FALSE,NULL);
			baseNode->message = message; //will be freed by http thread
			SetEvent(oldNode->eventHandle);
		}
	}
}

//Checks whether or not there is a local logging server alive, and checks in or becomes one as necessary
BOOL checkLogging(){
	//Become the logging server if nobody has yet
	//And set security rules so that all processes can send and receive data from me
	DWORD newSDsize;
	PSECURITY_DESCRIPTOR newSD;
	ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(D;;FA;;;NU)(A;;0x12019b;;;WD)(A;;0x12019f;;;CO)",
		SDDL_REVISION_1, &newSD, &newSDsize);
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = newSD;
	sa.bInheritHandle = FALSE;
	HANDLE servPipe = CreateNamedPipeA(LOCAL_REPORT_PIPE, PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE
		|WRITE_DAC, PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE, 1, 4000, 4000, 0, &sa);
	LocalFree(newSD); //Now we're done.
	//Did it work?
	if(servPipe == INVALID_HANDLE_VALUE)
		return checkIn(); //We're not the logging server. Just check in.
	return runLocalServer(servPipe);// Otherwise we are 
}

//Alert - size type pid argCount args... username...
void sendAlert(HOOKAPI_FUNC_CONF* conf, HOOKAPI_ACTION_CONF* action, void** calledArgPtr){
	disableAlerts(); //Don't allow recursive alerts!

	WCHAR username[UNLEN+1];
	DWORD userlen = UNLEN+1;
	if(GetUserNameW(username, &userlen) == FALSE)
		userlen = 0; // try to get username
	//Prepare a binary string
	string messageStr;
	//Add each parameter
	PHOOKAPI_ARG_CONF parameter = functionConfParameters(conf);
	for(unsigned int i = 0; i < conf->numArgs; i++){
		//get type
		string paramStr((char*)& (parameter->type), sizeof(parameter->type));
		//get value
		switch(parameter->type){
		case DWORD_HOOK:
		   paramStr.append((char*)&calledArgPtr[i], sizeof(calledArgPtr[i]));
		   break;
		case CSTRING:
		   if(calledArgPtr[i] != NULL)
			   paramStr.append((char*)calledArgPtr[i]);
		   break;
		case WCSTRING:
		   if(calledArgPtr[i] != NULL)
			   paramStr.append((char*)calledArgPtr[i], lstrlenW((wchar_t*)calledArgPtr[i]) * sizeof(wchar_t));
		   break;
		case BLOB_HOOK:
		   {
			   HOOKAPI_BLOB_ARG* blobArg = (HOOKAPI_BLOB_ARG*)parameter->value;
			   size_t size = blobArg->size;
			   if(blobArg->argument != -1)
				   size = (size_t)calledArgPtr[blobArg->argument];
			   if(calledArgPtr[i] != NULL)
				   paramStr.append((char*)calledArgPtr[i], size);
		   }
		}
		//add size
		size_t len = paramStr.length();
		if(len > INT_MAX)
			paramStr.erase(INT_MAX, len - INT_MAX);
		DWORD size = (DWORD)paramStr.length() + sizeof(size);
		messageStr.append((char*)&size,sizeof(size));
		messageStr.append(paramStr);
		//next
		parameter = nextArgConf(parameter);
	}
	DWORD usersize = (userlen - 1) * sizeof(WCHAR);
	messageStr.append((char*) &usersize, sizeof(DWORD));
	messageStr.append((char*) username, usersize); // append username

	//Get computer name
	if(computerName == NULL){
		GetComputerNameW(NULL, &computerNameLen);
		computerName = (PWCHAR)HeapAlloc(rwHeap, HEAP_ZERO_MEMORY, computerNameLen * sizeof(WCHAR));
		if(computerName == NULL || GetComputerNameW(computerName, &computerNameLen) == FALSE)
			computerNameLen = 0;
	}
	DWORD cnsize = computerNameLen * sizeof(WCHAR);
	messageStr.append((char*) &cnsize, sizeof(DWORD));
	messageStr.append((char*) computerName, cnsize); // append computer name

	//Get exe file name
	if(exeNameLen == 0)
		exeNameLen = GetModuleFileNameW(NULL, exeFileName, MAX_PATH);
	DWORD fnsize = exeNameLen * sizeof(WCHAR);
	messageStr.append((char*) &fnsize, sizeof(DWORD));
	messageStr.append((char*) exeFileName, fnsize); // append exe path name

	//Get module name from retaddr
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQuery(*(calledArgPtr-1), &meminfo, sizeof(meminfo));
	WCHAR modFileName[MAX_PATH];
	DWORD msize = GetModuleFileNameW((HMODULE)meminfo.AllocationBase, modFileName, MAX_PATH) * sizeof(WCHAR);
	messageStr.append((char*) &msize, sizeof(DWORD));
	messageStr.append((char*) modFileName, msize); // append module path name

	//Now we know total length
	HOOKAPI_MESSAGE message;
	message.length = (DWORD)messageStr.length() + sizeof(message);
	message.type = action->id;
	message.pid = GetCurrentProcessId();
	message.count = 1; //Single alert
	message.numArgs = conf->numArgs;

	//Put it all together into a complete message
	string completeMessage((char*)&message, sizeof(message));
	completeMessage.append(messageStr);
	DWORD numbytes = 0;
	//Send it! (locally)
	HANDLE pipe = CreateFileA(LOCAL_REPORT_PIPE, FILE_WRITE_DATA, 7, NULL, OPEN_ALWAYS,0,0);
	for(int i = 0; pipe == INVALID_HANDLE_VALUE && i < 10; i++){ // Up to 10 tries if it fails
		WaitNamedPipeA(LOCAL_REPORT_PIPE, 500);
		pipe = CreateFileA(LOCAL_REPORT_PIPE, FILE_WRITE_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			NULL,OPEN_EXISTING,0,0);
	}
	WriteFile(pipe, (PVOID)completeMessage.c_str(), (DWORD)completeMessage.length(), &numbytes, NULL);
	CloseHandle(pipe); //not really anything we can do if writing fails
	enableAlerts(); // back to normal
}
