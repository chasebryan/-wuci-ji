.global _start
.section .rodata
message:
  .ascii "lovelace-ghidra-smoke\n"
.section .text
_start:
  mov $1, %rax
  mov $1, %rdi
  lea message(%rip), %rsi
  mov $22, %rdx
  syscall
  mov $60, %rax
  xor %rdi, %rdi
  syscall
