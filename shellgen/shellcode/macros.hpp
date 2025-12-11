#pragma once

#include <Windows.h>

// Index should always start from 1
#define DEFVAR(name, index) constexpr unsigned long long name = 0xDEADBEEFDEADBEEF - index

// argument types should be in brackets
#define INLINE_CALL(returnType, address, argumentTypes, ...) reinterpret_cast<##returnType(*)##argumentTypes>(address)(__VA_ARGS__)

// define the function signiture
#define CODE_SIGNITURE(returnType, name) __declspec(noinline) returnType __CODE__##name

// Allocate no-memory (used for pointers to make compiler happy)
#define DUMMY_ALLOC(type) (type)VirtualAlloc(nullptr, NULL, NULL, NULL)

// define compile function signiture
#define COMPILE_SIGNITURE(name) __declspec(noinline) void __COMPILE__##name()

// calls the shellcode for use inside of the compile func
#define CALL_CODE(func, ...) __CODE__##func(__VA_ARGS__)

// Compiles COMPILE routine
#define COMPILE_CODE(group, name) group::__COMPILE__##name()