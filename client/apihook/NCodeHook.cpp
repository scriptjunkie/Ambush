#include "NCodeHook.h"
#include <Windows.h>

using namespace std;

// the disassembler needs at least 15
const unsigned int MaxInstructions = 30;

template <typename ArchT>
NCodeHook<ArchT>::NCodeHook(bool cleanOnDestruct, HANDLE rwxHeap)
	: MaxTotalTrampolineSize(ArchT::AbsJumpPatchSize * 2 + ArchT::MaxTrampolineSize),
	cleanOnDestruct_(cleanOnDestruct),
	trampolineHeap(rwxHeap)
{
	if(trampolineHeap == NULL || trampolineHeap == INVALID_HANDLE_VALUE)
		trampolineHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
}

template <typename ArchT>
NCodeHook<ArchT>::~NCodeHook()
{
	if (cleanOnDestruct_)
	{
		// restore all hooks and free memory (if possible)
		for(size_t i = hookedFunctions_.size(); i > 0; i--)
			removeHook(hookedFunctions_[i - 1]);
		HeapDestroy(trampolineHeap);
	}
}
inline opcodeAddr getJmpTarget(ud_t &ud_obj){
	ud_operand op = ud_obj.operand[0];
	if(op.type == UD_OP_JIMM){
		return (opcodeAddr)ud_obj.pc + op.lval.sdword;
	}else if (op.type == UD_OP_MEM && op.base == UD_R_RIP && op.index == UD_NONE && op.scale == 0){
		opcodeAddr* memaddr = (opcodeAddr*)((char*)ud_obj.pc + op.lval.sdword);
		return *memaddr;
	}
	return NULL;
}

template <typename ArchT>
opcodeAddr NCodeHook<ArchT>::getPatchSite(opcodeAddr codePtr, unsigned int* patchSize, bool* useAbsJump, 
		opcodeAddr trampoline, opcodeAddr& nextBlock, int& branchOffset, int& branchSize, opcodeAddr& branchTarget)
{
	// choose jump patch method
	unsigned int patchMinSize;
	*useAbsJump = architecture_.requiresAbsJump(codePtr, trampoline);
	if(*useAbsJump)
		patchMinSize = ArchT::AbsJumpPatchSize;
	else
		patchMinSize = ArchT::NearJumpPatchSize;
	const unsigned int MaxInstructions = 30;
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, ArchT::DisasmMode); // 32 or 64
	ud_set_input_buffer(&ud_obj, (uint8_t *)codePtr, MaxInstructions);

	/* disassembly loop */
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
			//We can handle a first jmp; just follow!
			if(ud_obj.pc - inslen == (uint64_t)codePtr && ud_obj.mnemonic == UD_Ijmp){
				return getPatchSite(target, patchSize, useAbsJump, trampoline, nextBlock, 
					branchOffset, branchSize, branchTarget);
			//we can also handle a last jmp; just send back where you need to jump to
			}else if(ud_obj.pc >= patchMinSize && ud_obj.mnemonic == UD_Ijmp){
				nextBlock = target;
				*patchSize = (unsigned int)(ud_obj.pc - (uint64_t)codePtr);
				return codePtr;
			}else{
				if(branchSize != -1)
					return (opcodeAddr)-1; //we're not handling multiple branches (yet)
				//near jmps (starting with 0x0f) are 2 bytes, short jumps are 1 byte
				branchSize = ((opcodeAddr)ud_obj.pc - inslen)[0] == 0x0f ? 2 : 1;
				branchOffset = (int)((opcodeAddr)ud_obj.pc - codePtr - inslen + branchSize);
				branchTarget = target;
			}
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
U NCodeHook<ArchT>::createHook(U originalFunc, U hookFunc)
{
	// choose jump patch method
	unsigned int patchSize;
	bool useAbsJump = false;

	// check if this is just a trampoline, and whether we need to follow or replace
	opcodeAddr trampolineAddr = (opcodeAddr)HeapAlloc(trampolineHeap, 0, MaxTotalTrampolineSize);
	opcodeAddr nextBlock = NULL;
	int branchOffset = -1;
	int branchSize = -1;
	opcodeAddr branchTarget = NULL;
	originalFunc = (U)getPatchSite((opcodeAddr)originalFunc, &patchSize, 
			&useAbsJump, trampolineAddr, nextBlock, branchOffset, branchSize, branchTarget);
	if(nextBlock == NULL)
		nextBlock = (opcodeAddr)originalFunc + patchSize;

	// error while determining offset?
	if ((char*)originalFunc == (char*)-1) return false;

	DWORD oldProtect = 0;
	BOOL retVal = VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!retVal) return false;

	// copy instructions to trampoline
	memcpy((void*)trampolineAddr, (void*)originalFunc, patchSize);
	architecture_.writeJump((opcodeAddr)originalFunc, (opcodeAddr)hookFunc);
	architecture_.writeJump(trampolineAddr + patchSize, nextBlock);

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

	DWORD dummy;
	VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, oldProtect, &dummy);

	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)trampolineAddr, MaxTotalTrampolineSize);
	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)originalFunc, useAbsJump ? ArchT::AbsJumpPatchSize : ArchT::NearJumpPatchSize);
	
	NCodeHookItem item((opcodeAddr)originalFunc, (opcodeAddr)hookFunc, trampolineAddr, patchSize);
	hookedFunctions_.insert(make_pair((opcodeAddr)hookFunc, item));

	return (U)trampolineAddr;
}

template <typename ArchT>
template <typename U> 
U NCodeHook<ArchT>::createHookByName(const string& dll, const string& funcName, U newFunc)
{
	U funcPtr = NULL;
	HMODULE hDll = LoadLibraryA(dll.c_str());
	funcPtr = (U)GetProcAddress(hDll, funcName.c_str());
	if (funcPtr != NULL) funcPtr = createHook(funcPtr, newFunc);
	FreeLibrary(hDll);
	return funcPtr;
}

template <typename ArchT>
template <typename U>
bool NCodeHook<ArchT>::removeHook(U address)
{
	// remove hooked function again, address points to the HOOK function!
	map<opcodeAddr, NCodeHookItem>::const_iterator result = hookedFunctions_.find((opcodeAddr)address);
	if (result != hookedFunctions_.end())
		return removeHook(result->second);
	return true;
}

template <typename ArchT>
bool NCodeHook<ArchT>::removeHook(NCodeHookItem item)
{
	// copy overwritten instructions back to original function
	DWORD oldProtect;
	BOOL retVal = VirtualProtect((LPVOID)item.OriginalFunc, item.PatchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!retVal) return false;
	memcpy((void*)item.OriginalFunc, (const void*)item.Trampoline, item.PatchSize);
	DWORD dummy;
	VirtualProtect((LPVOID)item.OriginalFunc, item.PatchSize, oldProtect, &dummy);
	
	hookedFunctions_.erase(item.HookFunc);
	freeTrampolines_.insert(item.Trampoline);
	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)item.OriginalFunc, item.PatchSize);
	
	return true;
}

template <typename ArchT> opcodeAddr NCodeHook<ArchT>::getFreeTrampoline(){
	if (freeTrampolines_.empty()) throw exception("No trampoline space available!");
	set<opcodeAddr>::iterator it = freeTrampolines_.begin();
	opcodeAddr result = *it;
	freeTrampolines_.erase(it);
	return result;
}