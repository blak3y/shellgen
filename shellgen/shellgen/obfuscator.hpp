#pragma once

#include "pe-analyser.hpp"
#include <random>

#include "fadec.h"
#include "fadec-enc.h"

namespace shellgen
{
    struct ObfuscatorSettings {
        bool junkInsertion = true;
        bool instructionSubstitution = true;
        bool constantEncoding = true;
        bool mbaObfuscation = false; // Heavy, off by default
        int mbaDepth = 1;            // Nesting level for MBA
    };

    class Obfuscator {
    public:
        static Obfuscator& Get() {
            static Obfuscator instance;
            return instance;
        }

        void Process(Function& function);
        void SetSeed(uint64_t seed) { m_Rng.seed(seed); }

        ObfuscatorSettings& Settings() { return m_Settings; }

    private:
        Obfuscator() : m_Rng(std::random_device{}()) {}

        void InsertJunk(uint8_t*& p);
        void EmitInstruction(uint8_t*& p, FdInstr& instr, uint8_t* original, int length);
        FeReg GetScratchReg(FeReg avoid1 = FE_NOREG, FeReg avoid2 = FE_NOREG, FeReg avoid3 = FE_NOREG);

        // MBA functions
        void EmitMbaAdd(uint8_t*& p, FeReg dst, FeReg src);
        void EmitMbaSub(uint8_t*& p, FeReg dst, FeReg src);
        void EmitMbaXor(uint8_t*& p, FeReg dst, FeReg src);
        void EmitMbaAnd(uint8_t*& p, FeReg dst, FeReg src);
        void EmitMbaOr(uint8_t*& p, FeReg dst, FeReg src);
        void EmitMbaConstant(uint8_t*& p, FeReg reg, int64_t value);

        std::mt19937 m_Rng;
        ObfuscatorSettings m_Settings;
    };
}