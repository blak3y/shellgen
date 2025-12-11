#pragma once

#include "pdbparse.hpp"

#include <filesystem>

namespace shellgen
{
	struct Function {
		std::vector<uint8_t> bytes;
		std::vector<uint32_t> variables;
		std::string group;
		FunctionMetadata metadata;
	};

	class FileAnalyser {
	public:
		FileAnalyser(std::filesystem::path& filePath, std::vector<shellgen::FunctionMetadata>& functions);
		~FileAnalyser();

		bool AnalyseFunctions(std::string searchTerm, std::vector<Function>& functions);
	private:
		void FindVariables(Function& function);

		std::vector<FunctionMetadata> m_Functions;
		uint8_t* m_LocalBuffer;
	};
}