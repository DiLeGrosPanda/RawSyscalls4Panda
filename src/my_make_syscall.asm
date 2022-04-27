.intel_syntax noprefix

.text
.global MyMakeSyscall

MyMakeSyscall:
  mov     r10, rcx
  syscall
  ret
