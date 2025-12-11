#include "pdbparse.hpp"

#pragma comment(lib, "dbghelp.lib")

#define NtCurrentProcess (HANDLE)(-1)

shellgen::PdbParse::PdbParse(std::filesystem::path& path) : m_Functions({})
{
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEBUG);
    if (!SymInitialize(NtCurrentProcess, NULL, FALSE)) {
        throw std::runtime_error(std::format("SymInitialize failed: {}", GetLastError()));
    }

    // Loading pdb into memory
    uint64_t baseAddress = 0x10000000;
    uint64_t loadedBase = SymLoadModuleEx(NtCurrentProcess, NULL, path.string().c_str(), NULL, baseAddress, 0x1000000, NULL, 0);
    if (!loadedBase)
    {
        SymCleanup(NtCurrentProcess);
        throw std::runtime_error("Ensure you are running in the same directory as the .pdb file");
    }

    // Enumerating functions
    SymEnumSymbols(NtCurrentProcess, loadedBase, "*", PdbParse::EnumerateFunctionsCallback, &m_Functions);

    // cleaning up dbghelp context
    SymUnloadModule64(NtCurrentProcess, loadedBase);
    SymCleanup(NtCurrentProcess);
}

shellgen::PdbParse::~PdbParse()
{
    m_Functions.clear();
}

std::vector<shellgen::FunctionMetadata>& shellgen::PdbParse::GetFunctionList()
{
    return m_Functions;
}

BOOL shellgen::PdbParse::EnumerateFunctionsCallback(PSYMBOL_INFO pSymbol, ULONG SymbolSize, PVOID UserContext)
{
    auto functions = reinterpret_cast<std::vector<shellgen::FunctionMetadata>*>(UserContext);
    if (!functions) {
        return FALSE; // return false exits callback
    }
    shellgen::FunctionMetadata meta{};
    meta.name = std::string(pSymbol->Name);
    meta.length = SymbolSize;
    meta.offset = pSymbol->Address - pSymbol->ModBase; // Get RVA of function
    functions->push_back(meta);
    return TRUE;
}