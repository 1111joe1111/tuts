from idaapi import *


def encode_val(val):
   return "".join(reversed(val)).encode("HEX")

bytecode_start = 0x4480C1
mov_r2_const = (0xed, 0x2a, 0x5a, 0xca)
mov_r1_offset = (0x99, 0x16, 0xa3)
mov_r0_offset = (0xc2, 0x76, 0x7a)

mov_r0_dword_r0 = (0xbf, 0xc6, 0xfa, 0x1C)
mov_r0_ebp = (0x8a,0x98, 0x68, 0x75, 0, 0x5b)
mov_dword_r0_r1 = (0x89,)
mov_var_r1 = (0x38, 0x05, 0x3c, 0x34, 0x18)


mov_var_r2 = (0x37,)
add_r1_r2 = (0x7c, 0x04)
nand_r1_r0 = (0xa9, 0x25, 0x5f)
nor_r2_r1 = (0x39, 0x0D)


byte_code = dbg_read_memory(bytecode_start, 800)
current = 0

while True:

    instruction = ord(byte_code[current])

    current += 1
    addr = hex(current + bytecode_start) + ": "

    if instruction in mov_r2_const:
        print addr + "mov r2, 0x" + encode_val(byte_code[current:current+4])
        current += 4

    elif instruction in mov_r1_offset:
        print addr + "mov r1, " + "[var_" + encode_val(byte_code[current]) + "]"
        current += 1

    elif instruction in mov_r0_offset:
        print addr + "mov r0, " + "[var_" + encode_val(byte_code[current]) + "]"
        current += 1

    elif instruction in mov_dword_r0_r1:
        print addr + "mov dword[r0], r1"

    elif instruction in mov_r0_dword_r0:
        print addr + "mov r0, dword[r0]"

    elif instruction in mov_r0_ebp:
        print addr + "mov r0, &r1"

    elif instruction in mov_var_r1:
        print addr + "mov [var_" + encode_val(byte_code[current]) + "], r1"
        current += 1

    elif instruction in mov_var_r2:
        print addr + "mov [var_" + encode_val(byte_code[current]) + "], r2"
        current += 1

    elif instruction in add_r1_r2:
        print addr + "add r1, r2"

    elif instruction in nand_r1_r0:
        print addr + "nand r1, r0"

    elif instruction in nor_r2_r1:
        print addr + "nor r1, r0"

    else:
        print "could not dissaseble instrction at: " + addr + hex(instruction)
        break

    if current > len(byte_code):
        break

