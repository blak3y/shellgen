#include <Windows.h>
#include <cstdio>

#include "shellcode/Console.hpp"

int main()
{
	size_t shellLength = sizeof(Console::Output::bytes);
	void* shellBuffer = VirtualAlloc(nullptr, shellLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellBuffer) {
		return 1;
	}

	*(void**)(Console::Output::bytes + Console::Output::variables[0]) = printf;
	memcpy(shellBuffer, Console::Output::bytes, shellLength);

	reinterpret_cast<void(*)(const char*)>(shellBuffer)("Hello World!\n");
}