#include <Windows.h>
#include <cstdio>

#include "shellcode/Console.hpp"

int main()
{
	FreeConsole();

	size_t shellLength = sizeof(Console::Output::bytes);
	void* shellBuffer = VirtualAlloc(nullptr, shellLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellBuffer) {
		return 1;
	}

	LoadLibraryA("user32.dll");
	LoadLibraryA("kernel32.dll");

	for (int i = 0; i < sizeof(Console::Output::dynamicImports) / sizeof(Console::ImportData); i++) {
		auto& dynamicImport = Console::Output::dynamicImports[i]; 
		
		HMODULE hModule = (HMODULE)GetModuleHandleA(dynamicImport.moduleName); 
		if (!hModule) {
			continue;
		} 
		
		unsigned long long proc = (unsigned long long)GetProcAddress((HMODULE)(hModule), dynamicImport.importName);
		
		if (!proc) {
			continue;
		} 
		
		*(unsigned long long*)(Console::Output::bytes + dynamicImport.offset) = proc;
	}

	*(void**)(Console::Output::bytes + Console::Output::variables[0]) = printf;
	memcpy(shellBuffer, Console::Output::bytes, shellLength);

	void* buffer = reinterpret_cast<void*(*)(const char*)>(shellBuffer)("Hello World!\n");
	printf("0x%llx\n", buffer);
	Sleep(5000);
	return 0;
}