#pragma once

#include "pe-analyser.hpp"

namespace shellgen
{
	class FileGenerator {
	public:
		FileGenerator(std::filesystem::path& folderPath, std::vector<Function>& functionList);
		~FileGenerator();

		void CreateFiles();
	private:
		std::string GenerateFileData(std::string group, std::vector<Function> functionList);

		std::vector<Function> m_FunctionList;
		std::filesystem::path m_FolderPath;
	};
}