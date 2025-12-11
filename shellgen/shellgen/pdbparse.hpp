#pragma once

#include <Windows.h>
#include <filesystem>
#include <dbghelp.h>

namespace shellgen
{
	struct FunctionMetadata {
		std::string name;
		uint32_t offset;
		size_t length;
	};

	class PdbParse {
	public:
		PdbParse(std::filesystem::path& path);
		~PdbParse();

		std::vector<shellgen::FunctionMetadata>& GetFunctionList();
	private:
		static BOOL EnumerateFunctionsCallback(PSYMBOL_INFO pSymbol, ULONG SymbolSize, PVOID UserContext);

		std::vector<FunctionMetadata> m_Functions;
	};
}