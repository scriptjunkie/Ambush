#pragma once 

#include <iostream>
#include <set>
#include <map>
#include <Windows.h>
#include "NCodeHookItem.h"
#include "udis/types.h"
#include "udis/extern.h"
#include "udis/itab.h"


class ArchitectureCommon
{
public:
	ArchitectureCommon() {};
	~ArchitectureCommon() {};

	template <typename ArchT>
	int getMinOffset(opcodeAddr codePtr, unsigned int jumpPatchSize);
	virtual bool requiresAbsJump(opcodeAddr from, opcodeAddr to) {
		size_t jmpDistance = from > to ? from - to : to - from;
		return jmpDistance <= 0x7FFF0000 ? false : true;
	};

	virtual void writeJump(opcodeAddr from, opcodeAddr to){
		if (requiresAbsJump(from, to)) writeAbsJump(from, to);
		else writeNearJump(from, to);
	}

	virtual void writeNearJump(opcodeAddr from, opcodeAddr to) =0;
	virtual void writeAbsJump(opcodeAddr from, opcodeAddr to) =0;
};

class ArchitectureIA32 : public ArchitectureCommon
{
public:
	ArchitectureIA32() {};
	~ArchitectureIA32() {};

	static const int DisasmMode = 32;
	static const unsigned int NearJumpPatchSize = sizeof(int) + 1;
	static const unsigned int AbsJumpPatchSize = sizeof(opcodeAddr) * 2 + 2;
	// max trampoline size = longest instruction (6) starting 1 byte before jump patch boundary
	static const unsigned int MaxTrampolineSize = AbsJumpPatchSize - 1 + 6;

	void writeNearJump(opcodeAddr from, opcodeAddr to)
	{
		unsigned char opcodes[NearJumpPatchSize];
		int offset = (int)(to - from - NearJumpPatchSize);
		opcodes[0] = 0xE9;
		*((int*)&opcodes[1]) = offset;
		memcpy((void*)from, opcodes, NearJumpPatchSize);
	}

	void writeAbsJump(opcodeAddr from, opcodeAddr to)
	{
		unsigned char opcodes[AbsJumpPatchSize];
		opcodes[0] = 0xFF;
		opcodes[1] = 0x25;
		*((opcodeAddr*)&opcodes[2]) = from + 6;
		*((opcodeAddr*)&opcodes[6]) = to;
		memcpy((void*)from, opcodes, AbsJumpPatchSize);
	}
};

class ArchitectureX64 : public ArchitectureIA32
{
public:
	ArchitectureX64() {};
	~ArchitectureX64() {};

	static const int DisasmMode = 64;
	static const unsigned int NearJumpPatchSize = sizeof(int) + 1;
	static const unsigned int AbsJumpPatchSize = sizeof(int) + sizeof(opcodeAddr) + 2;
	static const unsigned int MaxTrampolineSize = AbsJumpPatchSize - 1 + 6;

	void writeAbsJump(opcodeAddr from, opcodeAddr to){
		unsigned char opcodes[AbsJumpPatchSize];
		opcodes[0] = 0xFF;
		opcodes[1] = 0x25;
		*((int*)&opcodes[2]) = 0;
		*((opcodeAddr*)&opcodes[2 + sizeof(int)]) = to;
		memcpy((void*)from, opcodes, AbsJumpPatchSize);
	};
};

template <typename ArchT>
class NCodeHook
{
public:

	NCodeHook(bool cleanOnDestruct=true, HANDLE rwxHeap = NULL);
	~NCodeHook();

	template <typename U> U createHook(U originalFunc, U hookFunc);
	template <typename U> U createHookByName(const std::string& dll, const std::string& funcName, U newFunc);
	template <typename U> bool removeHook(U address);

private:
	// get rid of useless compiler warning C4512 by making operator= private
	NCodeHook& operator=(const NCodeHook&);

	opcodeAddr getFreeTrampoline();
	bool removeHook(NCodeHookItem item);
	opcodeAddr getPatchSite(opcodeAddr codePtr, unsigned int* patchSize, bool* useAbsJump, 
		opcodeAddr hookFunc, opcodeAddr& nextBlock, int& branchOffset, int& branchSize, opcodeAddr& branchTarget);
	HANDLE trampolineHeap;
	std::map<opcodeAddr, NCodeHookItem> hookedFunctions_;
	const unsigned int MaxTotalTrampolineSize;
	bool cleanOnDestruct_;
	ArchT architecture_;
};