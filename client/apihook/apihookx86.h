#pragma once
///////////////////////////////////////////////////////////////////////////////////////////
// This file defines x86-specific code for dynamically-generated code, etc.
///////////////////////////////////////////////////////////////////////////////////////////

#define GET_PEB "\x64\xa1\x30\x00\x00\x00\xc3" //mov eax,[fs:0x30]	 ret

#define SET_EAX "\x59\x58\xff\xe1" // pop ecx, pop eax, jmp ecx

#define GET_HOOK_ARG "\x89\xc8\xc3\x00" // mov eax, ecx; ret

#define STACK_FIXUP "\x5f\x5f\x5e\x5b\x59\xc2" //pop edi; pop edi; pop esi; pop ebx; pop ecx; ret [amount]
//for hook function tail: pop edi; pop edi; pop esi; pop ebx; mov esp,ebp; pop ebp; ret [amount]

#define POP_RET_ONE "\x5f\x5f\x5e\xc2\x04\x00" //pop edi; pop edi; pop esi; ret 4
#define POP_RET_THREE "\x5f\x5f\x5e\xc2\x0c\x00" //pop edi; pop edi; pop esi; ret C

#define CALL_API "\x8b\x54\x24\x04\x8b\x4c\x24\x08\x8b\x44\x24\x0c\x53\x85\xc9\x74\x09\x49\x8b\x1c\x8a\x53\x85\xc9\x75\xf7\xff\xd0\x5b\xc2\x0c\x00"
/*  //callApi: takes pointer to function args, count of args and function pointer, and makes the call
mov edx, [esp+4] // args
mov ecx, [esp+8] // count
mov eax, [esp+12]// func
push ebx

test ecx,ecx // while count != 0
jz done		// 
loop:
dec ecx			// count--
mov ebx, [edx+ecx*4] //get args[count]
push ebx
test ecx,ecx
jnz loop

done:
call eax  // call function
pop ebx
ret 12
*/

// mov ecx, arg; mov edx, hook; jmp edx
#pragma pack(1)
typedef struct sHOOKAPI_SPRINGBOARD
{
    unsigned char   movEcxOpcode;
    void*   argument;
    unsigned char   movEdxOpcode;
    void*   hookAddress;
    unsigned short int   jmpEdx;
} HOOKAPI_SPRINGBOARD, *PHOOKAPI_SPRINGBOARD;

inline PHOOKAPI_SPRINGBOARD getSpringboard(void* args, void* hook, HANDLE rwxHeap){
	//Get memory for springboard
	HOOKAPI_SPRINGBOARD* springboard = (HOOKAPI_SPRINGBOARD*)HeapAlloc(rwxHeap, 0, sizeof(HOOKAPI_SPRINGBOARD));
	if(springboard == NULL)
		return NULL;

	//Now make springboard code
	//Stores	 mov ecx, funcaddr	 mov edx, hookaddr	jmp edx
	//(ecx and edx are caller saved)
	springboard->movEcxOpcode = 0xb9;
	springboard->argument = args; // mov ecx, argument
	springboard->movEdxOpcode = 0xba;
	springboard->hookAddress = hook; // mov edx, hookaddr
	springboard->jmpEdx = 0xe2ff; // jmp edx
	return springboard;
}
