## ebpf-instruction-resolver

This tool aims to reduce an eBPF instruction file by getting rid of NOP (no-operation) instructions.

## Usage

1) g++ instruction_resolver.cpp -o prog
2) ./prog <path/to/insns.txt> 

*Note*: insns.txt is an ASCII representation of a program's eBPF instructions, where each line is an instruction. More specifically, it is an output of the [ebpf-extractor](https://github.com/smartnic/ebpf-extractor) tool.

## Background

When an instruction is optimized in K2 (e.g. 2 insns combined into 1), rather than removing the instruction in the output file, the instruction is replaced with a cheaper no-operation instruction. However, there is no "NOP" instruction in eBPF, so we define a NOP instruction as an unconditional jump (i.e., a jump that simply goes to the next instruction no matter what).

The reason why instructions are replaced with NOP instructions rather than be removed is because there will be several unresolved offsets. For example, a jump instruction in eBPF uses a local offset (i.e. it says to "jump 3 instructions forward). Thus, if an instruction is removed, this jump statement may suddenly refer to a different instruction, making the program no longer correct.

This tool fixes this issue by sequentially iterating through the program. If it encounters a NOP instruction, it ensures:

1) Jump instructions ABOVE the NOP instruction with jump destinations UNDER the NOP instruction have their offsets decreased by 1.

2) Jump instructions BELOW the NOP instruction with jump destinations ABOVE the NOP instruction have their offsets increased by 1.

With every iteration of the algorithm, then, the targeted destinations of each jump instruction is maintained. This means the final output is also correct.

## Difficulties

- there may be other eBPF instructions that utilize the 'offset' field in such a way that the program needs to account for.
- even if the instructions of a program still maintain correctness, other sections of an eBPF object file may have to be updated to account for the smaller number of instructions. This includes the offset of ELF sections, and internal content for ebpf-specific sections like relocations, maps, etc.
