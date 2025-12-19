#pragma once

#include "../macros.hpp"

#include <Windows.h>
#include <iostream>

namespace Console
{
	CODE_SIGNITURE(void, Output)(const char* string)
	{
		DEFVAR64(printf, 1);
		DEFVAR32(prot, 1);
		
		AllocConsole();

		INLINE_CALL(void, printf, (const char*), string);
	}
}