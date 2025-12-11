#include "file-analyser.hpp"

#include <fstream>
#include <iostream>

shellgen::FileAnalyser::FileAnalyser(std::filesystem::path& filePath, std::vector<shellgen::FunctionMetadata>& functions) : m_LocalBuffer(nullptr), m_Functions(functions)
{
	// manually map file into memory	
	std::vector<uint8_t> fileBytes = { };
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		throw std::runtime_error(std::format("Failed to read file: {}", filePath.string()));
	}

	// Get file length
	std::streampos fileLength = file.tellg();
	fileBytes.resize(fileLength);

	// Read all bytes of file into bytes
	file.seekg(0);
	file.read(reinterpret_cast<char*>(fileBytes.data()), fileLength);

	auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBytes.data());
	auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBytes.data() + dosHeader->e_lfanew);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		throw std::runtime_error("Invalid file format (expected PE)");
	}

	m_LocalBuffer = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!m_LocalBuffer) {
		throw std::runtime_error("Insufficent system resources, couldn't allocate image");
	}

	// Zero out buffer
	memset(m_LocalBuffer, NULL, ntHeaders->OptionalHeader.SizeOfImage);

	// Copy over headers
	memcpy(m_LocalBuffer, fileBytes.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

	// Copy over all sections
	auto section = IMAGE_FIRST_SECTION(ntHeaders);
	for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		memcpy(
			m_LocalBuffer + section->VirtualAddress,
			fileBytes.data() + section->PointerToRawData,
			section->SizeOfRawData
		);
		section++;
	}

	std::cout << std::format("Read {} from disk and loaded into memory\n", filePath.filename().string()) << std::endl;
}

shellgen::FileAnalyser::~FileAnalyser()
{
	m_Functions.clear();
	VirtualFree(m_LocalBuffer, NULL, MEM_RELEASE);
	std::cout << "\nCleaned up image from memory." << std::endl;
}

bool shellgen::FileAnalyser::AnalyseFunctions(std::string searchTerm, std::vector<Function>& functions)
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
		memcpy(parsedFunction.bytes.data(), m_LocalBuffer + function.offset, function.length);

		// Get all variables inside function
		FindVariables(parsedFunction);

		// Overwrite all variables with 0's
		for (auto offset : parsedFunction.variables)
		{
			*(uint64_t*)(parsedFunction.bytes.data() + offset) = NULL;
		}

		std::cout << std::format("Analysed {}::{}", parsedFunction.group, parsedFunction.metadata.name) << std::endl;
		std::cout << std::format("Group: {}", parsedFunction.group) << std::endl;
		std::cout << std::format("Bytes: {}", parsedFunction.bytes.size()) << std::endl;
		std::cout << std::format("Variables: {}", parsedFunction.variables.size()) << std::endl;

		functions.push_back(parsedFunction);
	}

	return true;
}

void shellgen::FileAnalyser::FindVariables(Function& function)
{
	int itterations = 0;
	while (itterations < 100)
	{
		size_t listSize = function.variables.size();
		uint64_t expectedValue = 0xDEADBEEFDEADBEEF - (listSize + 1);

		for (int i = 0; i < function.metadata.length; i++)
		{
			if (*(uint64_t*)(function.bytes.data() + i) == expectedValue)
			{
				expectedValue -= 1;
				function.variables.emplace_back(i);
				break;
			}
		}

		if (listSize == function.variables.size()) { // no variable was found
			break;
		}
		else {
			itterations++;
		}
	}
}


