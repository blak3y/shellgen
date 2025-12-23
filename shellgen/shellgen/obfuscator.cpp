#include "obfuscator.hpp"
#include <cstring>
#include "fadec.h"
#include "fadec-enc.h"

namespace shellgen
{
    // Convert decoder register format (FdReg 0-15) to encoder format (FeReg 0x100+)
    static inline FeReg FdRegToFeReg(int fdReg)
    {
        // FdReg: R0=0, R1=1, ..., R15=15
        // FeReg: AX=0x100, CX=0x101, ..., R15=0x10f
        return (FeReg)(0x100 + fdReg);
    }
    void Obfuscator::Process(Function& function)
    {
        std::vector<uint8_t> output;
        uint8_t buffer[256]; // Larger buffer for MBA expansion

        std::vector<std::pair<size_t, size_t>> importOffsetMap;
        for (size_t i = 0; i < function.dynamicImports.size(); i++) {
            importOffsetMap.emplace_back(function.dynamicImports[i].offset, i);
        }

        std::vector<std::pair<size_t, size_t>> variableOffsetMap;
        for (size_t i = 0; i < function.variables.size(); i++) {
            variableOffsetMap.emplace_back(function.variables[i].offset, i);
        }

        size_t offset = 0;
        FdInstr instr;

        while (offset < function.bytes.size())
        {
            size_t oldOffset = offset;
            uint8_t* p = buffer;

            int length = fd_decode(
                function.bytes.data() + offset,
                function.bytes.size() - offset,
                64, 0, &instr
            );

            if (length < 0) break;

            uint8_t* original = function.bytes.data() + offset;
            offset += length;

            bool hasImport = false;
            size_t importIndex = 0;
            size_t importOffsetInInstr = 0;

            for (auto& [oldOff, idx] : importOffsetMap) {
                if (oldOff >= oldOffset && oldOff < oldOffset + length) {
                    hasImport = true;
                    importIndex = idx;
                    importOffsetInInstr = oldOff - oldOffset;
                    break;
                }
            }

            bool hasVariable = false;
            size_t variableIndex = 0;
            size_t variableOffsetInInstr = 0;

            for (auto& [oldOff, idx] : variableOffsetMap) {
                if (oldOff >= oldOffset && oldOff < oldOffset + length) {
                    hasVariable = true;
                    variableIndex = idx;
                    variableOffsetInInstr = oldOff - oldOffset;
                    break;
                }
            }

            bool hasFixup = hasImport || hasVariable;

            if (!hasFixup && m_Settings.junkInsertion && (m_Rng() % 3) == 0) {
                InsertJunk(p);
            }

            size_t newInstrOffset = output.size() + (p - buffer);

            if (hasFixup) {
                std::memcpy(p, original, length);
                p += length;

                if (hasImport) {
                    function.dynamicImports[importIndex].offset = newInstrOffset + importOffsetInInstr;
                }
                if (hasVariable) {
                    function.variables[variableIndex].offset = newInstrOffset + variableOffsetInInstr;
                }
            }
            else {
                EmitInstruction(p, instr, original, length);
            }

            if (!hasFixup && m_Settings.junkInsertion && (m_Rng() % 4) == 0) {
                InsertJunk(p);
            }

            output.insert(output.end(), buffer, p);
        }

        function.bytes = output;
    }

    void Obfuscator::InsertJunk(uint8_t*& p)
    {
        int count = 1 + (m_Rng() % 3);

        for (int i = 0; i < count; i++) {
            FeReg reg = GetScratchReg();

            switch (m_Rng() % 8) {
            case 0:
                fe_enc64_impl(&p, FE_NOP, 0, 0, 0, 0);
                break;
            case 1:
                fe_enc64_impl(&p, FE_PUSHr, reg, 0, 0, 0);
                fe_enc64_impl(&p, FE_POPr, reg, 0, 0, 0);
                break;
            case 2:
                fe_enc64_impl(&p, FE_XCHG64rr, reg, reg, 0, 0);
                break;
            case 3:
                fe_enc64_impl(&p, FE_MOV64rr, reg, reg, 0, 0);
                break;
            case 4:
                fe_enc64_impl(&p, FE_LEA64rm, reg, FE_MEM(reg, 0, 0, 0), 0, 0);
                break;
            case 5:
                fe_enc64_impl(&p, FE_TEST64rr, reg, reg, 0, 0);
                break;
            case 6:
                fe_enc64_impl(&p, FE_CMP64ri, reg, 0, 0, 0);
                break;
            case 7:
                *p++ = 0x0F;
                *p++ = 0x1F;
                *p++ = 0x00;
                break;
            }
        }
    }

    void Obfuscator::EmitInstruction(uint8_t*& p, FdInstr& instr, uint8_t* original, int length)
    {
        int type = FD_TYPE(&instr);

        // MBA obfuscation for arithmetic/logic ops
        // CRITICAL: Never apply MBA to RSP/RBP - it uses push/pop which modifies the stack!
        if (m_Settings.mbaObfuscation) {
            // ADD reg, reg
            if (type == FDI_ADD &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                // Skip RSP (4) and RBP (5) - MBA uses stack operations
                if (dst_raw != 4 && dst_raw != 5 && (m_Rng() % 2) == 0) {
                    FeReg dst = FdRegToFeReg(dst_raw);
                    FeReg src = FdRegToFeReg(FD_OP_REG(&instr, 1));
                    EmitMbaAdd(p, dst, src);
                    return;
                }
            }

            // SUB reg, reg
            if (type == FDI_SUB &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                int src_raw = FD_OP_REG(&instr, 1);
                // Skip RSP (4) and RBP (5)
                if (dst_raw != 4 && dst_raw != 5 && dst_raw != src_raw && (m_Rng() % 2) == 0) {
                    EmitMbaSub(p, FdRegToFeReg(dst_raw), FdRegToFeReg(src_raw));
                    return;
                }
            }

            // XOR reg, reg (skip zeroing idiom)
            if (type == FDI_XOR &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                int src_raw = FD_OP_REG(&instr, 1);
                // Skip RSP (4) and RBP (5)
                if (dst_raw != 4 && dst_raw != 5 && dst_raw != src_raw && (m_Rng() % 2) == 0) {
                    EmitMbaXor(p, FdRegToFeReg(dst_raw), FdRegToFeReg(src_raw));
                    return;
                }
            }

            // AND reg, reg
            if (type == FDI_AND &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                // Skip RSP (4) and RBP (5)
                if (dst_raw != 4 && dst_raw != 5 && (m_Rng() % 2) == 0) {
                    FeReg dst = FdRegToFeReg(dst_raw);
                    FeReg src = FdRegToFeReg(FD_OP_REG(&instr, 1));
                    EmitMbaAnd(p, dst, src);
                    return;
                }
            }

            // OR reg, reg
            if (type == FDI_OR &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                // Skip RSP (4) and RBP (5)
                if (dst_raw != 4 && dst_raw != 5 && (m_Rng() % 2) == 0) {
                    FeReg dst = FdRegToFeReg(dst_raw);
                    FeReg src = FdRegToFeReg(FD_OP_REG(&instr, 1));
                    EmitMbaOr(p, dst, src);
                    return;
                }
            }

            // ADD reg, imm -> load to scratch with MBA, then MBA add
            // CRITICAL: Skip if dst is RSP/RBP - MBA uses stack operations!
            if (type == FDI_ADD &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
            {
                int dst_raw = FD_OP_REG(&instr, 0);
                int64_t imm = FD_OP_IMM(&instr, 1);
                // Don't obfuscate RSP (4) or RBP (5) - MBA uses push/pop!
                if (dst_raw != 4 && dst_raw != 5 && imm != 0 && (m_Rng() % 3) == 0) {
                    FeReg dst = FdRegToFeReg(dst_raw);
                    FeReg scratch = GetScratchReg(dst);
                    fe_enc64_impl(&p, FE_PUSHr, scratch, 0, 0, 0);
                    EmitMbaConstant(p, scratch, imm);
                    EmitMbaAdd(p, dst, scratch);
                    fe_enc64_impl(&p, FE_POPr, scratch, 0, 0, 0);
                    return;
                }
            }
        }

        // Standard substitutions (safe for RSP - no stack operations)
        if (m_Settings.instructionSubstitution) {
            // XOR reg, reg (zeroing) -> SUB reg, reg
            if (type == FDI_XOR &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_REG)
            {
                int r0_raw = FD_OP_REG(&instr, 0);
                int r1_raw = FD_OP_REG(&instr, 1);
                if (r0_raw == r1_raw && (m_Rng() % 2)) {
                    FeReg r0 = FdRegToFeReg(r0_raw);
                    fe_enc64_impl(&p, FE_SUB32rr, r0, r0, 0, 0);
                    return;
                }
            }

            // MOV reg, 0 -> XOR/SUB (safe for RSP)
            if (type == FDI_MOV &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_IMM &&
                FD_OP_IMM(&instr, 1) == 0)
            {
                FeReg reg = FdRegToFeReg(FD_OP_REG(&instr, 0));
                if (m_Rng() % 2) {
                    fe_enc64_impl(&p, FE_XOR32rr, reg, reg, 0, 0);
                }
                else {
                    fe_enc64_impl(&p, FE_SUB64rr, reg, reg, 0, 0);
                }
                return;
            }

            // INC -> ADD 1 (safe for RSP)
            if (type == FDI_INC && FD_OP_TYPE(&instr, 0) == FD_OT_REG) {
                FeReg reg = FdRegToFeReg(FD_OP_REG(&instr, 0));
                if (m_Rng() % 2) {
                    fe_enc64_impl(&p, FE_ADD64ri, reg, 1, 0, 0);
                    return;
                }
            }

            // DEC -> SUB 1 (safe for RSP)
            if (type == FDI_DEC && FD_OP_TYPE(&instr, 0) == FD_OT_REG) {
                FeReg reg = FdRegToFeReg(FD_OP_REG(&instr, 0));
                if (m_Rng() % 2) {
                    fe_enc64_impl(&p, FE_SUB64ri, reg, 1, 0, 0);
                    return;
                }
            }

            // SUB reg, imm -> ADD reg, -imm (safe for RSP)
            if (type == FDI_SUB &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
            {
                FeReg reg = FdRegToFeReg(FD_OP_REG(&instr, 0));
                int64_t imm = FD_OP_IMM(&instr, 1);
                if (m_Rng() % 2) {
                    fe_enc64_impl(&p, FE_ADD64ri, reg, (int32_t)(-imm), 0, 0);
                    return;
                }
            }
        }

        // Constant encoding
        if (m_Settings.constantEncoding) {
            // MOV reg, imm -> encoded
            if (type == FDI_MOV &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
            {
                int reg_raw = FD_OP_REG(&instr, 0);
                FeReg reg = FdRegToFeReg(reg_raw);
                int64_t imm = FD_OP_IMM(&instr, 1);

                // Don't obfuscate RSP (4) or RBP (5) with MBA (uses push/pop)
                if (imm != 0 && (m_Rng() % 3) == 0) {
                    if (m_Settings.mbaObfuscation && reg_raw != 4 && reg_raw != 5 && (m_Rng() % 2) == 0) {
                        EmitMbaConstant(p, reg, imm);
                    }
                    else {
                        uint32_t key = m_Rng();
                        fe_enc64_impl(&p, FE_MOV64ri, reg, (int32_t)(imm ^ key), 0, 0);
                        fe_enc64_impl(&p, FE_XOR64ri, reg, key, 0, 0);
                    }
                    return;
                }

                if (imm != 0 && (m_Rng() % 3) == 0) {
                    int32_t key = (int32_t)m_Rng();
                    fe_enc64_impl(&p, FE_MOV64ri, reg, (int32_t)(imm - key), 0, 0);
                    fe_enc64_impl(&p, FE_ADD64ri, reg, key, 0, 0);
                    return;
                }
            }

            // ADD reg, imm -> split (safe for RSP - doesn't use stack)
            if (type == FDI_ADD &&
                FD_OP_TYPE(&instr, 0) == FD_OT_REG &&
                FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
            {
                FeReg reg = FdRegToFeReg(FD_OP_REG(&instr, 0));
                int64_t imm = FD_OP_IMM(&instr, 1);
                if (imm != 0 && (m_Rng() % 3) == 0) {
                    int32_t a = (int32_t)(m_Rng() % 0xFFFF) - 0x7FFF;
                    int32_t b = (int32_t)(imm - a);
                    fe_enc64_impl(&p, FE_ADD64ri, reg, a, 0, 0);
                    fe_enc64_impl(&p, FE_ADD64ri, reg, b, 0, 0);
                    return;
                }
            }
        }

        // No substitution
        std::memcpy(p, original, length);
        p += length;
    }

    // x + y = (x ^ y) + 2*(x & y)
    void Obfuscator::EmitMbaAdd(uint8_t*& p, FeReg dst, FeReg src)
    {
        FeReg s1 = GetScratchReg(dst, src);
        FeReg s2 = GetScratchReg(dst, src, s1);

        fe_enc64_impl(&p, FE_PUSHr, s1, 0, 0, 0);
        fe_enc64_impl(&p, FE_PUSHr, s2, 0, 0, 0);

        // s1 = dst ^ src
        fe_enc64_impl(&p, FE_MOV64rr, s1, dst, 0, 0);
        fe_enc64_impl(&p, FE_XOR64rr, s1, src, 0, 0);

        // s2 = dst & src
        fe_enc64_impl(&p, FE_MOV64rr, s2, dst, 0, 0);
        fe_enc64_impl(&p, FE_AND64rr, s2, src, 0, 0);

        // s2 *= 2
        fe_enc64_impl(&p, FE_SHL64ri, s2, 1, 0, 0);

        // dst = s1 + s2
        fe_enc64_impl(&p, FE_MOV64rr, dst, s1, 0, 0);
        fe_enc64_impl(&p, FE_ADD64rr, dst, s2, 0, 0);

        fe_enc64_impl(&p, FE_POPr, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_POPr, s1, 0, 0, 0);
    }

    // x - y = (x ^ y) - 2*(~x & y)
    void Obfuscator::EmitMbaSub(uint8_t*& p, FeReg dst, FeReg src)
    {
        FeReg s1 = GetScratchReg(dst, src);
        FeReg s2 = GetScratchReg(dst, src, s1);

        fe_enc64_impl(&p, FE_PUSHr, s1, 0, 0, 0);
        fe_enc64_impl(&p, FE_PUSHr, s2, 0, 0, 0);

        // s1 = dst ^ src
        fe_enc64_impl(&p, FE_MOV64rr, s1, dst, 0, 0);
        fe_enc64_impl(&p, FE_XOR64rr, s1, src, 0, 0);

        // s2 = ~dst & src
        fe_enc64_impl(&p, FE_MOV64rr, s2, dst, 0, 0);
        fe_enc64_impl(&p, FE_NOT64r, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_AND64rr, s2, src, 0, 0);

        // s2 *= 2
        fe_enc64_impl(&p, FE_SHL64ri, s2, 1, 0, 0);

        // dst = s1 - s2
        fe_enc64_impl(&p, FE_MOV64rr, dst, s1, 0, 0);
        fe_enc64_impl(&p, FE_SUB64rr, dst, s2, 0, 0);

        fe_enc64_impl(&p, FE_POPr, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_POPr, s1, 0, 0, 0);
    }

    // x ^ y = (x | y) - (x & y)
    void Obfuscator::EmitMbaXor(uint8_t*& p, FeReg dst, FeReg src)
    {
        FeReg s1 = GetScratchReg(dst, src);
        FeReg s2 = GetScratchReg(dst, src, s1);

        fe_enc64_impl(&p, FE_PUSHr, s1, 0, 0, 0);
        fe_enc64_impl(&p, FE_PUSHr, s2, 0, 0, 0);

        // s1 = dst | src
        fe_enc64_impl(&p, FE_MOV64rr, s1, dst, 0, 0);
        fe_enc64_impl(&p, FE_OR64rr, s1, src, 0, 0);

        // s2 = dst & src
        fe_enc64_impl(&p, FE_MOV64rr, s2, dst, 0, 0);
        fe_enc64_impl(&p, FE_AND64rr, s2, src, 0, 0);

        // dst = s1 - s2
        fe_enc64_impl(&p, FE_MOV64rr, dst, s1, 0, 0);
        fe_enc64_impl(&p, FE_SUB64rr, dst, s2, 0, 0);

        fe_enc64_impl(&p, FE_POPr, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_POPr, s1, 0, 0, 0);
    }

    // x & y = (x + y) - (x | y)
    void Obfuscator::EmitMbaAnd(uint8_t*& p, FeReg dst, FeReg src)
    {
        FeReg s1 = GetScratchReg(dst, src);
        FeReg s2 = GetScratchReg(dst, src, s1);

        fe_enc64_impl(&p, FE_PUSHr, s1, 0, 0, 0);
        fe_enc64_impl(&p, FE_PUSHr, s2, 0, 0, 0);

        // s1 = dst + src
        fe_enc64_impl(&p, FE_MOV64rr, s1, dst, 0, 0);
        fe_enc64_impl(&p, FE_ADD64rr, s1, src, 0, 0);

        // s2 = dst | src
        fe_enc64_impl(&p, FE_MOV64rr, s2, dst, 0, 0);
        fe_enc64_impl(&p, FE_OR64rr, s2, src, 0, 0);

        // dst = s1 - s2
        fe_enc64_impl(&p, FE_MOV64rr, dst, s1, 0, 0);
        fe_enc64_impl(&p, FE_SUB64rr, dst, s2, 0, 0);

        fe_enc64_impl(&p, FE_POPr, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_POPr, s1, 0, 0, 0);
    }

    // x | y = (x + y) - (x & y)
    void Obfuscator::EmitMbaOr(uint8_t*& p, FeReg dst, FeReg src)
    {
        FeReg s1 = GetScratchReg(dst, src);
        FeReg s2 = GetScratchReg(dst, src, s1);

        fe_enc64_impl(&p, FE_PUSHr, s1, 0, 0, 0);
        fe_enc64_impl(&p, FE_PUSHr, s2, 0, 0, 0);

        // s1 = dst + src
        fe_enc64_impl(&p, FE_MOV64rr, s1, dst, 0, 0);
        fe_enc64_impl(&p, FE_ADD64rr, s1, src, 0, 0);

        // s2 = dst & src
        fe_enc64_impl(&p, FE_MOV64rr, s2, dst, 0, 0);
        fe_enc64_impl(&p, FE_AND64rr, s2, src, 0, 0);

        // dst = s1 - s2
        fe_enc64_impl(&p, FE_MOV64rr, dst, s1, 0, 0);
        fe_enc64_impl(&p, FE_SUB64rr, dst, s2, 0, 0);

        fe_enc64_impl(&p, FE_POPr, s2, 0, 0, 0);
        fe_enc64_impl(&p, FE_POPr, s1, 0, 0, 0);
    }

    // c = (c | k) + (c & ~k) for any k
    void Obfuscator::EmitMbaConstant(uint8_t*& p, FeReg reg, int64_t value)
    {
        // Check if value fits in 32-bit signed immediate
        if (value >= INT32_MIN && value <= INT32_MAX) {
            // Use MBA obfuscation with 32-bit key
            uint32_t k = m_Rng();
            int64_t part1 = (int64_t)((uint64_t)value | (uint64_t)k);
            int64_t part2 = (int64_t)((uint64_t)value & ~(uint64_t)k);

            FeReg scratch = GetScratchReg(reg);

            fe_enc64_impl(&p, FE_PUSHr, scratch, 0, 0, 0);

            fe_enc64_impl(&p, FE_MOV64ri, reg, (int32_t)part1, 0, 0);
            fe_enc64_impl(&p, FE_MOV64ri, scratch, (int32_t)part2, 0, 0);
            fe_enc64_impl(&p, FE_ADD64rr, reg, scratch, 0, 0);

            fe_enc64_impl(&p, FE_POPr, scratch, 0, 0, 0);
        }
        else {
            // Fallback for large 64-bit values: use XOR encoding
            uint32_t key = m_Rng();
            fe_enc64_impl(&p, FE_MOV64ri, reg, (int32_t)((value >> 32) ^ key), 0, 0);
            fe_enc64_impl(&p, FE_XOR64ri, reg, key, 0, 0);
            fe_enc64_impl(&p, FE_SHL64ri, reg, 32, 0, 0);
            fe_enc64_impl(&p, FE_ADD64ri, reg, (int32_t)(value & 0xFFFFFFFF), 0, 0);
        }
    }

    FeReg Obfuscator::GetScratchReg(FeReg avoid1, FeReg avoid2, FeReg avoid3)
    {
        // Use R10, R11, R12, R13 as scratch registers
        constexpr FeReg regs[] = { FE_R10, FE_R11, FE_R12, FE_R13 };

        // Collect available registers
        FeReg available[4];
        int count = 0;

        for (FeReg reg : regs) {
            if (reg != avoid1 && reg != avoid2 && reg != avoid3) {
                available[count++] = reg;
            }
        }

        // Should always have at least one available since we have 4 scratch regs
        // and at most 3 avoid params
        if (count == 0) {
            // Fallback - should never happen with 4 scratch regs
            return FE_R10;
        }

        return available[m_Rng() % count];
    }
}