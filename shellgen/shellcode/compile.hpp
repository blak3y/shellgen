#pragma once

#include "groups/console.hpp"

void compile()
{
	CALL_CODE(Console, Output, DUMMY_ALLOC(char*));
}