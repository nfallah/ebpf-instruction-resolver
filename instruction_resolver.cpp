    #include <string>
    #include <fstream>
    #include <iostream>
    #include <cstdint>
    #include <vector>
    #include <sstream>

    #define BPF_JMP 0x05
    #define BPF_JMP32 0x06

    struct bpf_insn {
        uint8_t code;
        uint8_t dst_reg;
        uint8_t src_reg;
        int16_t off;
        int32_t imm;
    };

    int main(int argc, char *argv[]) {
        if (argc != 2) {
            return 1;
        }
        std::ifstream infile{argv[1]};
        if (!infile) {
            return 1;
        }
        std::string line;
        std::vector<bpf_insn> insns;
        while (std::getline(infile, line)) {
            line = line.substr(1, line.size() - 2);
            std::istringstream stream{line};
            bpf_insn insn{};
            unsigned int tmp_code, tmp_src_reg, tmp_dst_reg;
            stream >> tmp_code >> tmp_src_reg >> tmp_dst_reg >> insn.off >> insn.imm;
            if (!stream) {
                return 1;
            }
            insn.code = static_cast<uint8_t>(tmp_code);
            insn.src_reg = static_cast<uint8_t>(tmp_src_reg);
            insn.dst_reg = static_cast<uint8_t>(tmp_dst_reg);
            insns.push_back(insn);
        }
        infile.close();
        const size_t start_size = insns.size();
        size_t i = 0;
        while (i < insns.size()) {
            const bpf_insn& curr_insn = insns[i];
            bool is_nop = (curr_insn.code == BPF_JMP || curr_insn.code == BPF_JMP32) && curr_insn.off == 0;
            if ( !is_nop) {
                ++i;
                continue;
            }
            bool is_jmp_dst = false;
            for (int j = 0; j < insns.size(); ++j) {
                if (i == j) {
                    continue;
                }
                const bpf_insn& target_insn = insns[j];
                bool jumps_to_curr = (target_insn.code == BPF_JMP || target_insn.code == BPF_JMP32) &&
                                    j + target_insn.off + 1 == i;
                if (jumps_to_curr) {
                    is_jmp_dst = true;
                    break;
                }
            }
            if (is_jmp_dst) {
                ++i;
                continue;    
            }
            for (int j = 0; j < i; ++j) {
                bpf_insn& target_insn = insns[j];
                if (target_insn.code != BPF_JMP && target_insn.code != BPF_JMP32) {
                    continue;
                }
                if (j + target_insn.off + 1 > i) {
                    --target_insn.off;
                }
            }
            for (int j = i + 1; j < insns.size(); ++j) {
                bpf_insn& target_insn = insns[j];
                if (target_insn.code != BPF_JMP && target_insn.code != BPF_JMP32) {
                    continue;
                }
                if (j + target_insn.off + 1 < i) {
                    ++target_insn.off;
                }
            }
            // Keep 'i' the same, and remove the NOP instruction.
            insns.erase(insns.begin() + i);
        }
        size_t instructions_removed = start_size - insns.size();
        std::cout << "Reduced program by " << instructions_removed << " instruction" << (instructions_removed == 1 ? "" : "s") << std::endl;
        std::ofstream outfile{"resolved.txt"};
        if (!outfile) {
            return 1;
        }
        bool first_line = true;
        for (const bpf_insn& insn : insns) {
            if (!first_line) {
                outfile << '\n';
            } else {
                first_line = false;
            }
            outfile << "{" << static_cast<unsigned int>(insn.code) 
                    << " " << static_cast<unsigned int>(insn.src_reg)
                    << " " << static_cast<unsigned int>(insn.dst_reg) 
                    << " " << insn.off 
                    << " " << insn.imm << "}";
        }
        outfile.close();
        return 0;
    }