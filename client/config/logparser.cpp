#include <windows.h>
#include <iostream>
#include <string>
#include "../apihook/signatures.h"
#include "../apihook/apihook.h"
using namespace std;

void dumpLog(HANDLE inputHandle){
	//First get time
	SYSTEMTIME systime;
	FILETIME filetime;
	DWORD read;
	if(ReadFile(inputHandle, &filetime, sizeof(filetime), &read, NULL) == FALSE || read != sizeof(filetime))
		return;
	if(FileTimeToSystemTime(&filetime, &systime))
		wcout << systime.wYear << "-" << systime.wMonth << "-" << systime.wDay << " " << systime.wHour 
		<< ":" << systime.wMinute << ":" << systime.wSecond << "." << systime.wMilliseconds; //get time

	// Then get full message
	HOOKAPI_MESSAGE message;
	if(ReadFile(inputHandle, &message, sizeof(message), &read, NULL) == FALSE || read != sizeof(message))
		return;
	PBYTE contents = new BYTE[message.length + 2];
	memcpy(contents, &message, sizeof(message));
	// if length > size - position it will overflow
	if(message.length - sizeof(message) > GetFileSize(inputHandle, NULL) - SetFilePointer(inputHandle, 0, NULL, FILE_CURRENT)){
		cerr << "Error! Invalid message length: " << message.length << endl;
		return;
	}
	if(ReadFile(inputHandle, contents + sizeof(message), message.length - sizeof(message), &read, NULL) == FALSE 
			|| read != message.length - sizeof(message))
		return;
	wcout << " Type " << message.type << " pid " << message.pid << " count " << message.count << " numargs " << message.numArgs;

	//Handle string messages (error/start)
	PBYTE data = contents + sizeof(message);
	if(((int)message.type) < 0){
		contents[message.length] = 0;
		contents[message.length + 1] = 0;
		if(message.type == START_INFO)
			wcout << " Process start";
		else if(message.type == ERROR_INFO)
			wcout << " ERROR";
		wcout << " " << (PWCHAR)data << endl;
		dumpLog(inputHandle);
		return;
	}

	//Now get args
	for(unsigned int i = 0; i < message.numArgs; i++){
		//get value
		DWORD totallen =  *((PDWORD)data);
		//Check length against total message length
		if(totallen + (data - contents) > message.length || (data - contents) < sizeof(DWORD)*2){
			cerr << "Error! Invalid argument size" << endl;
			return;
		}
		DWORD datalen = totallen - sizeof(DWORD)*2;
		DWORD type = ((PDWORD)data)[1];
		PCHAR val = (PCHAR)(data + sizeof(DWORD)*2);
		switch(type){
		case DWORD_HOOK:
			wcout << " " << *((PDWORD)val);
			break;
		case CSTRING:
			{
			string valstring(val, datalen);
			cout << valstring << " ";
			break;
			}
		case WCSTRING:
			{
			wstring wvalstring((PWCHAR)val, datalen / sizeof(WCHAR));
			wcout << wvalstring << " ";
			break;
			}
		case BLOB_HOOK:
			{
			string valstring(val, datalen);
			cout << valstring << " ";
			break;
			}
		}
		data = data + ((PDWORD)data)[0];
	}

	//Get username, computername, exename, modname
	for(int i = 0; i < 4; i++){
		DWORD wstringsize = ((PDWORD)data)[0];
		//Check length against total message length
		if(wstringsize + (data - contents) > message.length || (data - contents) < sizeof(DWORD)){
			cerr << "Error! Invalid wstring size" << endl;
			return;
		}
		data = data + sizeof(DWORD);
		wstring wstr((PWCHAR)data, wstringsize / sizeof(WCHAR));
		wcout << "  " << wstr;
		data = data + wstringsize;
	}
	delete [] contents;
	wcout << endl;
	dumpLog(inputHandle); //Recurse to go on
}