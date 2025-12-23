#pragma once

#include "pdbparse.hpp"

#include <filesystem>
#include <cstdint>
#include <unordered_map>

namespace shellgen
{
	struct DynamicImport {
		std::string moduleName;
		std::string functionName;
		uint32_t offset;
	};
	
	struct Variable {
		uint32_t offset;
	};

	struct Function {
		std::vector<uint8_t> bytes;
		std::vector<Variable> variables;
		std::vector<DynamicImport> dynamicImports;
		std::string group;
		FunctionMetadata metadata;
	};

	struct ImportData {
		std::string moduleName;
		std::string functionName;
	};

	class PeAnalyser {
	public:
		PeAnalyser(std::vector<shellgen::FunctionMetadata>& functions);
		~PeAnalyser();

		bool AnalyseFunctions(std::string searchTerm, std::vector<Function>& functions);
	private:
		void FindVariables(Function& function);
		void RebuildImports(Function& function);
		void BuildImportLookupTable();

		std::vector<FunctionMetadata> m_Functions;
		std::unordered_map<uint64_t, ImportData> m_ImportLookup;
		uint8_t* m_ImageBase;
	};
}