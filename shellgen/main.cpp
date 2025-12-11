#include "shellgen/shellgen.hpp"
#include "shellcode/compile.hpp"

int main()
{
	shellgen::GenerateFile();
	
	// will cause crash
	compile();
}