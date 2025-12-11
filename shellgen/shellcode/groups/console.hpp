#pragma once

#include "../macros.hpp"

namespace Console
{
	CODE_SIGNITURE(void, Output)(const char* string)
	{
		DEFVAR(printf, 1);

		INLINE_CALL(void, printf, (const char*), string);
	}

	COMPILE_SIGNITURE(Output)
	{
		const char* str = DUMMY_ALLOC(char*);
		CALL_CODE(Output, str);
	}
}