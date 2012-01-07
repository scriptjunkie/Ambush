#include "NCodeHook.h"
#include <Windows.h>

using namespace std;

// the disassembler needs at least 15
const unsigned int MaxInstructions = 30;

template <typename ArchT>
NCodeHook<ArchT>::NCodeHook(bool cleanOnDestruct, HANDLE rwxHeap)
	: MaxTotalTrampolineSize(ArchT::AbsJumpPatchSize + ArchT::MaxTrampolineSize),
	cleanOnDestruct_(cleanOnDestruct),
	forceAbsJmp_(false), 
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

template <typename ArchT>
const unsigned char* NCodeHook<ArchT>::getPatchSite(const unsigned char* codePtr, 
										unsigned int* patchSize, bool* useAbsJump, void* hookFunc)
{
	// choose jump patch method
	unsigned int patchMinSize;
	*useAbsJump = forceAbsJmp_ || architecture_.requiresAbsJump((uintptr_t)codePtr, (uintptr_t)hookFunc);
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
	while(ud_obj.pc - (uint64_t)codePtr < patchMinSize)
		//Disassembly errors or jump/calls
		if ((inslen = ud_disassemble(&ud_obj)) == 0 || 
				(ud_obj.mnemonic >= UD_Ijo && ud_obj.mnemonic <= UD_Ijmp) ||
				ud_obj.mnemonic == UD_Icall){
			//We can handle a first jump; just follow!
			if(ud_obj.pc - inslen == (uint64_t)codePtr && ud_obj.mnemonic == UD_Ijmp){
				ud_operand op = ud_obj.operand[0];
				if(op.type == UD_OP_JIMM){
					return getPatchSite((const unsigned char*)ud_obj.pc 
						+ op.lval.sdword, patchSize, useAbsJump, hookFunc);
				}else if (op.type == UD_OP_MEM && op.base == UD_R_RIP && op.index == UD_NONE && op.scale == 0){
					const unsigned char** memaddr = (const unsigned char**)((char*)ud_obj.pc + op.lval.sdword);
					return getPatchSite(*memaddr, patchSize, useAbsJump, hookFunc);
				}
			}
			return (const unsigned char*)-1;
		}

	// if we were unable to disassemble enough instructions we fail
	if (ud_obj.pc - (uint64_t)codePtr < patchMinSize) return (const unsigned char*)-1;

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
	originalFunc = (U)getPatchSite((const unsigned char*)originalFunc, &patchSize, &useAbsJump, hookFunc);
	
	// error while determining offset?
	if ((char*)originalFunc == (char*)-1) return false;

	DWORD oldProtect = 0;
	BOOL retVal = VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!retVal) return false;

	// get trampoline memory and copy instructions to trampoline
	uintptr_t trampolineAddr = (uintptr_t)HeapAlloc(trampolineHeap, 0, MaxTotalTrampolineSize);
	memcpy((void*)trampolineAddr, (void*)originalFunc, patchSize);
	if (useAbsJump)
	{
		architecture_.writeAbsJump((uintptr_t)originalFunc, (uintptr_t)hookFunc);
		architecture_.writeAbsJump(trampolineAddr + patchSize, (uintptr_t)originalFunc + patchSize);
	}
	else
	{
		architecture_.writeNearJump((uintptr_t)originalFunc, (uintptr_t)hookFunc);
		architecture_.writeNearJump(trampolineAddr + patchSize, (uintptr_t)originalFunc + patchSize);
	}

	DWORD dummy;
	VirtualProtect((LPVOID)originalFunc, ArchT::MaxTrampolineSize, oldProtect, &dummy);

	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)trampolineAddr, MaxTotalTrampolineSize);
	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)originalFunc, useAbsJump ? ArchT::AbsJumpPatchSize : ArchT::NearJumpPatchSize);
	
	NCodeHookItem item((uintptr_t)originalFunc, (uintptr_t)hookFunc, trampolineAddr, patchSize);
	hookedFunctions_.insert(make_pair((uintptr_t)hookFunc, item));

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
	map<uintptr_t, NCodeHookItem>::const_iterator result = hookedFunctions_.find((uintptr_t)address);
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

template <typename ArchT>
uintptr_t NCodeHook<ArchT>::getFreeTrampoline()
{
	if (freeTrampolines_.empty()) throw exception("No trampoline space available!");
	set<uintptr_t>::iterator it = freeTrampolines_.begin();
	uintptr_t result = *it;
	freeTrampolines_.erase(it);
	return result;
}