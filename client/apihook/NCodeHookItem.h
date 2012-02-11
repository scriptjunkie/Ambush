#pragma once

#include <iostream>
typedef unsigned char* opcodeAddr;

struct NCodeHookItem
{
	NCodeHookItem() : OriginalFunc(0), HookFunc(0), PatchSize(0), Trampoline(0) {};
	NCodeHookItem(opcodeAddr of, opcodeAddr hf, opcodeAddr tp, unsigned int ps)
		: OriginalFunc(of), HookFunc(hf), Trampoline(tp), PatchSize(ps)
	{
	};
	opcodeAddr OriginalFunc;
	opcodeAddr HookFunc;
	unsigned int PatchSize;
	opcodeAddr Trampoline;
};