#include "pe-analyser.hpp"

#include <unordered_map>
#include <fstream>
#include <iostream>

#include "fadec.h"
#include "fadec-enc.h"

shellgen::PeAnalyser::PeAnalyser(std::vector<shellgen::FunctionMetadata>& functions) : m_Functions(functions), m_ImportLookup({})
{
	m_ImageBase = reinterpret_cast<uint8_t*>(GetModuleHandle(nullptr));
	BuildImportLookupTable();
}

shellgen::PeAnalyser::~PeAnalyser()
{
	m_ImportLookup.clear();
	m_Functions.clear();
}

bool shellgen::PeAnalyser::AnalyseFunctions(std::string searchTerm, std::vector<Function>& functions)
{
	for (auto& function : m_Functions)
	{
		if (!(function.name.find(searchTerm) != std::string::npos)) {
			continue; // skip all functions that don't match search term
		}

		Function parsedFunction{};
		parsedFunction.metadata = function;

		// Parsing group name
		size_t groupOffset = function.name.find_first_of(':');
		if (groupOffset == std::string::npos) {
			parsedFunction.group = "unknown";
		}
		else {
			parsedFunction.group = function.name.substr(0, groupOffset);
			if (parsedFunction.group.empty()) {
				parsedFunction.group = "global";
			}
		}

		// Fixing function name
		size_t signitureOffset = parsedFunction.metadata.name.find_last_of('_');
		if (groupOffset != std::string::npos) {
			parsedFunction.metadata.name = parsedFunction.metadata.name.substr(signitureOffset + 1, parsedFunction.metadata.name.size() - signitureOffset);
		}

		// Copying over bytes
		parsedFunction.bytes.resize(function.length);
		memcpy(parsedFunction.bytes.data(), m_ImageBase + function.offset, function.length);

		// Rebuilding all import calls inside of function
		RebuildImports(parsedFunction);

		// Get all variables inside function
		FindVariables(parsedFunction);

		std::cout << std::format("Analysed {}::{}", parsedFunction.group, parsedFunction.metadata.name) << std::endl;
		std::cout << std::format("Group: {}", parsedFunction.group) << std::endl;
		std::cout << std::format("Bytes: {}", parsedFunction.bytes.size()) << std::endl;
		std::cout << std::format("Variables: {}", parsedFunction.variables.size()) << std::endl;
		std::cout << std::format("Imports: {}", parsedFunction.dynamicImports.size()) << std::endl;

		functions.push_back(parsedFunction);
	}

	return true;
}

void shellgen::PeAnalyser::FindVariableType(Function& function, const uint8_t type)
{
	printf("Looking for variables of size %i\n", type);

	uint64_t signiture = 0xDEADBEEFDEADBEEF;

	int itterations = 0;
	while (itterations < 100)
	{
		size_t listSize = 0;
		for (auto var : function.variables) {
			if (var.type == type) {
				listSize++;
			}
		}

		printf("listSize: %i\n", listSize);

		bool hasFound = false;
		for (int i = 0; i < function.metadata.length; i++)
		{
			switch (type)
			{
			case 1:
				if (*(uint8_t*)(function.bytes.data() + i) == 0xAA - (listSize + 1))
				{
					function.variables.emplace_back(type, i);
					*(uint8_t*)(function.bytes.data() + i) = 0;
					hasFound = true;
				}
				break;
			case 2:
				if (*(uint16_t*)(function.bytes.data() + i) == 0xFACE - (listSize + 1))
				{
					function.variables.emplace_back(type, i);
					*(uint16_t*)(function.bytes.data() + i) = 0;
					hasFound = true;
				}
				break;
			case 4:
				if (*(uint32_t*)(function.bytes.data() + i) == 0xCAFEBABE - (listSize + 1))
				{
					function.variables.emplace_back(type, i);
					*(uint32_t*)(function.bytes.data() + i) = 0;
					hasFound = true;
				}
				break;
			case 8:
				if (*(uint64_t*)(function.bytes.data() + i) == 0xDEADC0DEBEEFCAFE - (listSize + 1))
				{
					function.variables.emplace_back(type, i);
					*(uint64_t*)(function.bytes.data() + i) = 0;
					hasFound = true;
				}
				break;
			}
		}

		if (!hasFound) { // no variable was found
			break;
		}
		else {
			printf("Variable found with size %i\n", type);
			itterations++;
		}
	}
}

void shellgen::PeAnalyser::FindVariables(Function& function)
{
	uint8_t variableSize[] = { 8, 4, 2, 1 };
	for (int i = 0; i < sizeof(variableSize); i++)
	{
		FindVariableType(function, variableSize[i]);
	}
}

void shellgen::PeAnalyser::RebuildImports(Function& function)
{
	std::vector<uint8_t> rebuiltBytes = {};

	// Get all imports called inside of function
	size_t functionOffset = 0;
	FdInstr instruction{};
	while (functionOffset < function.bytes.size())
	{
		// Decode the current instruction in the function
		int instructionLength = fd_decode(function.bytes.data() + functionOffset, function.bytes.size() - functionOffset, 64, 0, &instruction);
		if (instructionLength < 0) {
			break; // failed to decode instruction
		}

		uint8_t* instructionStart = function.bytes.data() + functionOffset;
		uint8_t* instructionEnd = instructionStart + instructionLength;
		functionOffset += instructionLength; // so we don't have to rewrite this every continue statement

		// skip any instructions that arent relative calls
		if (FD_TYPE(&instruction) != FDI_CALL ||
			FD_OP_TYPE(&instruction, 0) != FD_OT_MEM ||
			FD_OP_BASE(&instruction, 0) != FD_REG_IP) {
			rebuiltBytes.insert(rebuiltBytes.end(), instructionStart, instructionEnd);
			continue;
		}

		int64_t callOffset = FD_OP_DISP(&instruction, 0);
		uint64_t importAddress = (function.metadata.offset + functionOffset) + callOffset; // resolve iat address referenced (instructionLength is added at start of func)

		auto importEntry = m_ImportLookup.find(importAddress);
		if (importEntry == m_ImportLookup.end()) {
			std::cout << std::format("Failed to find import for relative call in {}::{}", function.group, function.metadata.name) << std::endl;
			rebuiltBytes.insert(rebuiltBytes.end(), instructionStart, instructionEnd);
			continue;
		}

		std::cout << std::format("{}!{} called inside of {}::{}", importEntry->second.moduleName, importEntry->second.functionName, function.group, function.metadata.name) << std::endl;

		// define buffer and instruction pointer
		uint8_t encodedBytes[32]{};
		uint8_t* encodePointer = encodedBytes;

		// encode the instructions to do an absolute jump
		fe_enc64_impl(&encodePointer, FE_MOV64ri, FE_AX, 0xDEADBEEFDEADBEEF /* put 8byte value here to avoid optimisation */, 0, 0);
		fe_enc64_impl(&encodePointer, FE_CALLr, 0, 0, 0, 0);

		// zero out 8 byte value
		*(uint64_t*)(encodedBytes + 2) = 0;

		DynamicImport dynamicImport{};
		dynamicImport.functionName = importEntry->second.functionName;
		dynamicImport.moduleName = importEntry->second.moduleName;
		dynamicImport.offset = rebuiltBytes.size() + 2; // current function offset + size of mov rax
		function.dynamicImports.emplace_back(dynamicImport);

		rebuiltBytes.insert(rebuiltBytes.end(), encodedBytes, encodedBytes + (encodePointer - encodedBytes));
	}

	function.bytes = rebuiltBytes;
}

void shellgen::PeAnalyser::BuildImportLookupTable()
{
	auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_ImageBase);
	auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(m_ImageBase + dosHeader->e_lfanew);
	auto& importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importDirectory.VirtualAddress || !importDirectory.Size) {
		return;
	}

	auto importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(m_ImageBase + importDirectory.VirtualAddress);
	while (importDescriptor->Name)
	{
		auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(m_ImageBase + importDescriptor->OriginalFirstThunk);
		uint64_t importOffset = importDescriptor->FirstThunk;

		while (thunk->u1.AddressOfData)
		{
			if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
			{
				auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(m_ImageBase + thunk->u1.AddressOfData);
				m_ImportLookup[importOffset] = { (char*)m_ImageBase + importDescriptor->Name, importByName->Name };
			}

			importOffset += sizeof(uint64_t);
			thunk++;
		}

		importDescriptor++;
	}
}


