from elftools.elf.elffile import ELFFile
from capstone import *
import struct


def replace_nop_with_mov(binary_path, target_function):
    with open(binary_path, "r+b") as f:  # 使用 "r+b" 模式打开以便修改文件
        elf = ELFFile(f)
        symbol_table = elf.get_section_by_name('.symtab')
        if not symbol_table:
            print("No symbol table (.symtab) found!")
            return

        # 找到目标函数
        target_symbol = None
        for symbol in symbol_table.iter_symbols():
            if symbol.name == target_function:
                target_symbol = symbol
                break

        if not target_symbol:
            print(f"No '{target_function}' function found in the symbol table!")
            return

        func_addr = target_symbol['st_value']
        func_size = target_symbol['st_size']
        print(f"'{target_function}' function found at 0x{func_addr:x}, size {func_size} bytes")

        # 定位函数所在的节并提取数据
        for section in elf.iter_sections():
            if section['sh_addr'] <= func_addr < section['sh_addr'] + section['sh_size']:
                section_data = section.data()
                section_offset = func_addr - section['sh_addr']
                func_data = section_data[section_offset:section_offset + func_size]
                section_start = section['sh_offset']  # 节在文件中的偏移
                break
        else:
            print(f"Could not find the section containing '{target_function}'!")
            return

        # 使用 Capstone 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        nop_offsets = []  # 记录 NOP 指令的偏移
        for instruction in md.disasm(func_data, func_addr):
            if instruction.mnemonic == "nop":
                offset_in_func = instruction.address - func_addr
                nop_offsets.append(offset_in_func)


        ##生成四个NOP指令,
        # 第一个将x3寄存器赋值为0
        nop_data1 = b"\x03\x00\x80\xd2"  # mov x3, #0
        # 第二个将x4寄存器设置为全1（0xFFFFFFFF）
        nop_data2 = b"\x04\x00\x80\x92"  # mov x4, #-1
        #第三个将x0赋值为x0
        nop_data3 = b"\x84\x30\x83\x9a"  #csel x0, x4, x3, ne
        #第四个为ADD X8 X8 X4
        nop_data4 = b"\x08\x01\x04\x8a"  # add x8, x8, x4
        ##将四个NOP指令替换为上述指令
        l = [nop_data1, nop_data2, nop_data3, nop_data4]
        ## 开始替换 NOP 指令,只替换四个NOP指令
        for i in range(4):
            if i < len(nop_offsets):
                # 计算目标地址
                target_addr = section_start + section_offset + nop_offsets[i]
                # 计算 MOV 指令
                mov_insn = l[i] # mov x0, x0
                # 写入数据
                f.seek(target_addr)
                f.write(mov_insn)
                print(f"Replaced NOP at 0x{target_addr:x} with MOV")

        # for offset in nop_offsets:
        #     # 计算目标地址
        #     target_addr = section_start + section_offset + offset
        #     # 计算 MOV 指令
        #     mov_insn = b"\x40\x00\x80\xd2"  # mov x0, x0
        #     # 写入数据
        #     f.seek(target_addr)
        #     f.write(mov_insn)
        #     print(f"Replaced NOP at 0x{target_addr:x} with MOV")

if __name__ == "__main__":
    binary_file = 'havepatch'  # 替换为你的二进制文件路径
    target_function = 'victim_function'  # 替换为目标函数名称
    try:
        replace_nop_with_mov(binary_file, target_function)
    except FileNotFoundError:
        print(f"Error: File {binary_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
