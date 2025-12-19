#include "shellgen/shellgen.hpp"
#include "shellcode/compile.hpp"

int main()
{
	shellgen::GenerateFile();
	
	// Will never run but forces compilation of shellcode
	if (DUMMY_ALLOC(void*)) {
		compile();
	}
}