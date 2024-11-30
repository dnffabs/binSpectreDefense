from elftools.elf.elffile import ELFFile
from capstone import *


def disassemble_main_function(binary_path,function_name):
    # 打开二进制文件
    with (open(binary_path, "rb") as f):
        elf = ELFFile(f)
        # 查找符号表
        symbol_table = elf.get_section_by_name('.symtab')
        if not symbol_table:
            print("No symbol table (.symtab) found!")
            return
        # 查找函数符号
        function_symbol = None
        for symbol in symbol_table.iter_symbols():
            if symbol.name == function_name:
                function_symbol= symbol
                break

        if not function_symbol:
            print("No 'victim_function' function found in the symbol table!")
            return
        # 获取函数地址和大小
        func_addr = function_symbol['st_value']
        func_size = function_symbol['st_size']
        print(f"'{function_name}' function found at 0x{func_addr:x}, size {func_size} bytes")

        # 查找函数所在的节
        for section in elf.iter_sections():
            if section['sh_addr'] <= func_addr < section['sh_addr'] + section['sh_size']:
                section_data = section.data()
                section_offset = func_addr - section['sh_addr']
                func_data = section_data[section_offset:section_offset + func_size]
                break
        else:
            print(f"Could not find the section containing 'main'!")
            return

        # 使用 Capstone 反汇编
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        print(f"\nDisassembling {function_name} function:")
        for instruction in md.disasm(func_data, func_addr):
            print(f"0x{instruction.address:08x}:\t{instruction.mnemonic}\t{instruction.op_str}")


if __name__ == "__main__":

    ####在命令行输入二进制文件路径，如：python armDisassembly.py ./spectre
    # 即可反汇编二进制文件中的 main 函数
    binary_file = input("Enter the path of the binary file: ")
    function_name = input("Enter the name of the function to disassemble: ")
    try:
        disassemble_main_function(binary_file,function_name)
    except FileNotFoundError:
        print(f"Error: File {binary_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")