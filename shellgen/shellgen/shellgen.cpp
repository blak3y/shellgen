#include "shellgen.hpp"

#include "pdbparse.hpp"
#include "file-analyser.hpp"
#include "file-generator.hpp"

#include <filesystem>
#include <iostream>

void shellgen::GenerateFile()
{
	std::filesystem::path currentPath = std::filesystem::current_path();
	std::filesystem::path pdbPath = currentPath / "shellgen.pdb";
	std::filesystem::path filePath = currentPath / "shellgen.exe";
	std::filesystem::path outputPath = currentPath / "shellcode/";

	try {
		auto pdb = std::make_unique<PdbParse>(pdbPath);
		auto functionList = pdb->GetFunctionList();
		if (functionList.empty()) {
			throw std::runtime_error("Failed to parse symbols from pdb.");
		}

		auto analyser = std::make_unique<FileAnalyser>(filePath, functionList);

		std::vector<Function> parsedFunctionList{};
		if (!analyser->AnalyseFunctions("__CODE__", parsedFunctionList)) {
			throw std::runtime_error("Failed to analyse functions.");
		}

		auto generator = std::make_unique<FileGenerator>(outputPath, parsedFunctionList);
		generator->CreateFiles();
	}
	catch (const std::exception& e) {
		std::cout << "An exception occured: " << e.what() << std::endl;
	}
}
