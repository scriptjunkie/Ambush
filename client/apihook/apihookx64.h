#pragma once
///////////////////////////////////////////////////////////////////////////////////////////
// This file defines x64-specific code for dynamically-generated code, etc.
///////////////////////////////////////////////////////////////////////////////////////////

#define GET_PEB "\x65\x48\x8b\x04\x25\x60\x00\x00\x00\xc3" // mov rax, [gs:96];    ret

#define SET_EAX "\x48\x89\xc8\xc3" // mov rax, rcx;  ret

#define STACK_FIXUP "\xc3"   //ret; Caller-cleaned stack on x64. YAY!

#define GET_HOOK_ARG "\x4c\x89\xd0\xc3"  // mov rax, r10;  ret

#define POP_RET_ONE "\xc3" // ret; Caller-cleaned stack on x64. YAY!
#define POP_RET_THREE POP_RET_ONE

#define CALL_API "\x53\x48\x89\xd3\x48\x83\xec\x20\x48\x85\xd2\x74\x0d\x48\xff\xca\x48\x8b\x04\xd1\x50\x48\x85\xd2\x75\xf3\x4c\x89\xc0\x48\x8b\x0c\x24\x48\x8b\x54\x24\x08\x4c\x8b\x44\x24\x10\x4c\x8b\x4c\x24\x18\xff\xd0\x48\x85\xdb\x74\x09\x5a\x48\xff\xcb\x48\x85\xdb\x75\xf7\x48\x83\xc4\x20\x5b\xc3"
/*  //callApi: takes pointer to function args, count of args and function pointer, and makes the call
// rcx = args
// rdx = count
// r8 = func
push rbx
mov rbx, rdx
sub rsp, 0x20

test rdx,rdx // while count != 0
jz done

loop:
dec rdx		 // count--
mov rax, [rcx+rdx*8] //get args[count]
push rax
test rdx,rdx
jnz loop

done:
mov rax, r8  // rax = func

// set up registers
mov rcx, [rsp]
mov rdx, [rsp+8]
mov r8,  [rsp+0x10]
mov r9,  [rsp+0x18]
call rax  // call function
// clean up. :-(

test rbx,rbx // while count-- != 0
jz doret

restoreloop:
pop rdx
dec rbx
test rbx,rbx
jnz restoreloop

doret:
add rsp, 0x20
pop rbx
ret
*/

#pragma pack(1)
typedef struct sHOOKAPI_SPRINGBOARD
{
    unsigned short   movR10Opcode;
    void*   argument;
    unsigned short   movR11Opcode;
    void*   hookAddress;
    unsigned int   jmpR11;
} HOOKAPI_SPRINGBOARD, *PHOOKAPI_SPRINGBOARD;

inline PHOOKAPI_SPRINGBOARD getSpringboard(void* args, void* hook, HANDLE rwxHeap){
	//Get memory for springboard
	HOOKAPI_SPRINGBOARD* springboard = (HOOKAPI_SPRINGBOARD*)HeapAlloc(rwxHeap, 0, sizeof(HOOKAPI_SPRINGBOARD));
	if(springboard == NULL)
		return NULL;

	//Now make springboard code
	//(r10 and r11 are caller saved)
	springboard->movR10Opcode = 0xba49;
	springboard->argument = args; // mov r10, argument
	springboard->movR11Opcode = 0xbb49;
	springboard->hookAddress = hook; // mov r11, hookaddr
	springboard->jmpR11 = '\x41\xff\xe3\x00'; // jmp r11
	return springboard;
}
