#pragma once

#include "../macros.hpp"

#include <Windows.h>
#include <iostream>

namespace Console
{
	CODE_SIGNITURE(void*, Output)(const char* string)
	{
		DEFVAR64(printf, 1);
		
		void* output = nullptr;
		bool val = false;
		if (string) {
			AllocConsole();
			val = true;
		}

		if (val) {
			output = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		INLINE_CALL(void, printf, (const char*), string);
		return output;
	}
}