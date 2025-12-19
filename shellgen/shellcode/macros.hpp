#pragma once

#include <Windows.h>

// Index should always start from 1
#define DEFVAR64(name, index) constexpr unsigned long long name = 0xDEADC0DEBEEFCAFE - index
#define DEFVAR32(name, index) constexpr unsigned long name = 0xCAFEBABE - index
#define DEFVAR16(name, index) constexpr unsigned short name = 0xFACE - index
#define DEFVAR8(name, index)  constexpr unsigned char name = 0xAA - index

// argument types should be in brackets
#define INLINE_CALL(returnType, address, argumentTypes, ...) reinterpret_cast<##returnType(*)##argumentTypes>(address)(__VA_ARGS__)

// define the function signiture
#define CODE_SIGNITURE(returnType, name) __declspec(noinline) returnType __CODE__##name

// Allocate no-memory (used for pointers to make compiler happy)
#define DUMMY_ALLOC(type) (type)VirtualAlloc(nullptr, NULL, NULL, NULL)

// calls the shellcode for use inside of the compile func
#define CALL_CODE(group, func, ...) group::__CODE__##func(__VA_ARGS__)