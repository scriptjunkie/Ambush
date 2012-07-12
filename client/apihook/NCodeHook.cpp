#include "NCodeHook.h"
#include <Windows.h>
using namespace std;

template <typename ArchT>
NCodeHook<ArchT>::NCodeHook(HANDLE rwxHeap)
	: MaxTotalTrampolineSize(ArchT::AbsJumpPatchSize * 2 + ArchT::MaxTrampolineSize),
	trampolineHeap(rwxHeap){
	if(trampolineHeap == NULL || trampolineHeap == INVALID_HANDLE_VALUE)
		trampolineHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
}

inline opcodeAddr getJmpTarget(ud_t &ud_obj){
	ud_operand op = ud_obj.operand[0];
	if(op.type == UD_OP_JIMM){
		switch (op.size) {
			case  8:
				return (opcodeAddr)(ud_obj.pc + op.lval.sbyte); 
			case 16:
				return (opcodeAddr)(ud_obj.pc + op.lval.sword);
			case 32:
				return (opcodeAddr)(ud_obj.pc + op.lval.sdword);
			default:
				return NULL;
		}
	}else if (op.type == UD_OP_MEM){
		if(op.base == UD_R_RIP && op.index == UD_NONE && op.scale == 0){
			opcodeAddr* memaddr = (opcodeAddr*)((char*)ud_obj.pc + op.lval.sdword);
			return *memaddr;
		}else if(op.base == UD_NONE && op.index == UD_NONE && op.scale == 0){
			opcodeAddr* memaddr = (opcodeAddr*)(op.lval.uqword);
			return *memaddr;
		}
	}
	return NULL;
}

template <typename ArchT>
opcodeAddr NCodeHook<ArchT>::getPatchSite(opcodeAddr codePtr, // where to start
		unsigned int* patchSize, // size of instructions to copy to trampoline
		bool* useAbsJump, opcodeAddr hookFunction, // to calculate what kind of jump
		opcodeAddr& nextBlock, // Where to go after the hookFunction
		int& branchOffset, int& branchSize, opcodeAddr& branchTarget, // for branch relinking
		opcodeAddr*& swapAddr, // Address for pointer swap style hooking
		unsigned short *& winapiPatchPoint){ // Address of mov edi,edi to be overwritten with back jump
	if(*((int*)codePtr) == 0) //if it's all zeros, this isn't a function!
		return (opcodeAddr)-1;
	// choose jump patch method
	unsigned int patchMinSize;
	*useAbsJump = architecture_.requiresAbsJump(codePtr, hookFunction);
	if(*useAbsJump)
		patchMinSize = ArchT::AbsJumpPatchSize;
	else
		patchMinSize = ArchT::NearJumpPatchSize;
	const unsigned int MaxInstructions = 30;
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, ArchT::DisasmMode); // 32 or 64
	ud_set_input_buffer(&ud_obj, (uint8_t *)codePtr, MaxInstructions);

	// disassembly loop 
	ud_set_pc(&ud_obj, (uint64_t)codePtr);
	unsigned int inslen = 0;
	while(ud_obj.pc - (uint64_t)codePtr < patchMinSize){
		//Disassembly errors or jump/calls
		if ((inslen = ud_disassemble(&ud_obj)) == 0 || 
				(ud_obj.mnemonic >= UD_Ijo && ud_obj.mnemonic <= UD_Ijmp) ||
				ud_obj.mnemonic == UD_Icall){
			opcodeAddr target = getJmpTarget(ud_obj);
			if(target == NULL) //can't identify target :-(
				return (opcodeAddr)-1;
			//Jmp at start; follow and see if we can hook the real function
			if(ud_obj.pc - inslen == (uint64_t)codePtr && ud_obj.mnemonic == UD_Ijmp){
				opcodeAddr recursiveAnswer = getPatchSite(target, patchSize, useAbsJump, 
					hookFunction, nextBlock, branchOffset, branchSize, branchTarget, swapAddr, winapiPatchPoint);
				//No luck? If we have an x64-style import address, just swap the addresses to hook
				ud_operand op = ud_obj.operand[0];
				if(recursiveAnswer == (opcodeAddr)-1 && op.type == UD_OP_MEM && op.base == UD_R_RIP 
						&& op.index == UD_NONE && op.scale == 0){
					swapAddr = (opcodeAddr*)((char*)ud_obj.pc + op.lval.sdword);
					return (opcodeAddr)-1;
				}
				return recursiveAnswer; //Otherwise we just return the recursive answer, regardless
			//Jump at end? Just send back where you need to jump to
			}else if(ud_obj.pc - (uint64_t)codePtr >= patchMinSize && ud_obj.mnemonic == UD_Ijmp){
				nextBlock = target;
				*patchSize = (unsigned int)(ud_obj.pc - (uint64_t)codePtr);
				return codePtr;
			//And we can also relink branches, although this is kind of risky and might be removed
			}else{
				if(branchSize != -1)
					return (opcodeAddr)-1; //we're not handling multiple branches
				//near jmps (starting with 0x0f) are 2 bytes, short jumps are 1 byte
				branchSize = ((opcodeAddr)ud_obj.pc - inslen)[0] == 0x0f ? 2 : 1;
				branchOffset = (int)((opcodeAddr)ud_obj.pc - codePtr - inslen + branchSize);
				branchTarget = target;
			}
		// nop nop nop nop nop  mov edi,edi for winapi patch points
		}else if(ud_obj.pc - inslen == (uint64_t)codePtr && ud_obj.mnemonic == UD_Imov 
				&& *((PUSHORT)codePtr) == 0xFF8B &&
				(memcmp(codePtr-5,"\xCC\xCC\xCC\xCC\xCC",5) == 0 ||
				memcmp(codePtr-5,"\x90\x90\x90\x90\x90",5) == 0)
				&& !architecture_.requiresAbsJump(codePtr - 5, hookFunction)){
			winapiPatchPoint = (unsigned short *)codePtr;
			nextBlock = codePtr + 2; //Resume after our patch
			*patchSize = 0; 
			return codePtr - 5;
		//Refuse if interrupt or the hook would run off end of function, and squash other code
		}else if(ud_obj.mnemonic == UD_Iint ||
				(ud_obj.pc - (uint64_t)codePtr < patchMinSize && ud_obj.mnemonic == UD_Iret)){
			return (opcodeAddr)-1;
		}
	}

	// if we were unable to disassemble enough instructions we fail
	if (ud_obj.pc - (uint64_t)codePtr < patchMinSize)
		return (opcodeAddr)-1;

	*patchSize = (unsigned int)(ud_obj.pc - (uint64_t)codePtr);
	return codePtr;
}

// create a new hook for "hookFunc" and return the trampoline which can be used to
// call the original function without the hook
template <typename ArchT>
template <typename U> 
bool NCodeHook<ArchT>::createHook(U originalFunc, U hookFunc, U* trampAddr){
	if(originalFunc == NULL) //whoops
		return false;
	// choose jump patch method
	unsigned int patchSize;
	bool useAbsJump = false;

	// check if this is just a trampoline, and whether we need to follow or replace
	opcodeAddr trampolineAddr = (opcodeAddr)HeapAlloc(trampolineHeap, 0, MaxTotalTrampolineSize);
	*trampAddr = (U)trampolineAddr; // Set up jump back from hook before hook is set up in case function is in use
	opcodeAddr nextBlock = NULL;  // Where we go to after the trampoline
	int branchOffset = -1;
	opcodeAddr branchTarget = NULL;  // Branch relinking stuff
	int branchSize = -1;
	opcodeAddr* swapAddr = NULL; // Address of address to swap
	unsigned short * winapiPatchPoint = NULL; // Where to write a short jump back for winapi hooks
	originalFunc = (U)getPatchSite((opcodeAddr)originalFunc, &patchSize, &useAbsJump, (opcodeAddr)hookFunc, 
			nextBlock, branchOffset, branchSize, branchTarget, swapAddr, winapiPatchPoint);
	if(nextBlock == NULL)
		nextBlock = (opcodeAddr)originalFunc + patchSize;

	if(swapAddr != NULL){ // Let's do a swap if that is an option
		*(opcodeAddr*)trampAddr = *swapAddr;
		*swapAddr = (opcodeAddr)hookFunc;
		HeapFree(trampolineHeap, 0, trampolineAddr);
		return true;
	}
	if ((char*)originalFunc == (char*)-1)
		return false; //Ok. We tried everything, and it still didn't work. *sigh*

	DWORD oldProtect = 0;
	BOOL retVal = VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!retVal) return false;

	//No trampoline necessary if no instructions to reconstruct!
	if(patchSize == 0){
		HeapFree(trampolineHeap, 0, trampolineAddr); //get rid of it
		*(opcodeAddr*)trampAddr = nextBlock;
	}else{ // copy instructions to trampoline
		memcpy((void*)trampolineAddr, (void*)originalFunc, patchSize);
		architecture_.writeJump(trampolineAddr + patchSize, nextBlock);
		FlushInstructionCache(GetCurrentProcess(), (LPCVOID)trampolineAddr, MaxTotalTrampolineSize);
	}

	// relink branch by adding another jmp to the end of the trampoline used only by the branch:
	// the trampoline will look like this:   
	// nop; nop; jge branchJump; nop; jmp nextBlock; branchJump: jmp branchTarget
	if(branchTarget != NULL){
		//find out what value to write and where
		opcodeAddr branchJump = trampolineAddr + ArchT::AbsJumpPatchSize + ArchT::MaxTrampolineSize;
		size_t branchDistance = branchJump - (trampolineAddr + branchOffset + branchSize);
		//write it, whether 8 bit or 16 bit
		if(branchSize == 1)
			trampolineAddr[branchOffset] = (BYTE)branchDistance;
		else
			((unsigned short*)trampolineAddr + branchOffset)[0] = (unsigned short)branchDistance;
		architecture_.writeJump(branchJump, branchTarget); // now write jump from branch to final branch target
	}
	architecture_.writeJump((opcodeAddr)originalFunc, (opcodeAddr)hookFunc); //Now we hook it up
	if(winapiPatchPoint != NULL)
		*winapiPatchPoint = 0xF9EB; // JMP $-5

	DWORD dummy;
	VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, oldProtect, &dummy);

	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)originalFunc, useAbsJump ? ArchT::AbsJumpPatchSize : ArchT::NearJumpPatchSize);

	return true;
}
