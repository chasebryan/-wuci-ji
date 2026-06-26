.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global write_all
.global fill_random
.global read_key_file
.global read_artifact_file
.global open_seal_file_paths
.global close_seal_files
.global open_output_file
.global write_open_plaintext
.global create_open_temp
.global unlink_path
.global rename_noreplace_path
.extern hex32_decode
.extern io_buf
.extern aead_text_len
.extern aead_output_path
.extern seal_input_fd
.extern seal_output_fd
.extern seal_file_mode
.extern aead_open_buf
.extern hex_buf
.extern open_temp_path
.extern open_temp_fd

write_all:
    push rbx
    push r12
    push r13
    mov r13, rdi
    mov rbx, rsi
    mov r12, rdx
.Lwrite_all_loop:
    test r12, r12
    jz .Lwrite_all_ok
    mov eax, SYS_WRITE
    mov rdi, r13
    mov rsi, rbx
    mov rdx, r12
    syscall
    cmp rax, 0
    jle .Lwrite_all_err
    add rbx, rax
    sub r12, rax
    jmp .Lwrite_all_loop
.Lwrite_all_ok:
    xor eax, eax
    jmp .Lwrite_all_done
.Lwrite_all_err:
    mov eax, 1
.Lwrite_all_done:
    pop r13
    pop r12
    pop rbx
    ret

fill_random:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
.Lfill_random_loop:
    test r12, r12
    jz .Lfill_random_ok
    mov eax, SYS_GETRANDOM
    mov rdi, rbx
    mov rsi, r12
    xor edx, edx
    syscall
    cmp rax, 0
    jle .Lfill_random_fail
    add rbx, rax
    sub r12, rax
    jmp .Lfill_random_loop
.Lfill_random_ok:
    mov eax, 1
    jmp .Lfill_random_done
.Lfill_random_fail:
    xor eax, eax
.Lfill_random_done:
    pop r12
    pop rbx
    ret

read_key_file:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, FILE_READ_FLAGS
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lread_key_file_fail

    mov r13, rax
    mov eax, SYS_READ
    mov rdi, r13
    lea rsi, [rip + hex_buf]
    mov edx, KEYFILE_READ_MAX
    syscall
    mov rbx, rax

    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall

    test rbx, rbx
    js .Lread_key_file_fail
    cmp rbx, 64
    jb .Lread_key_file_fail
    cmp rbx, 64
    je .Lread_key_file_decode
    cmp rbx, 65
    jne .Lread_key_file_fail
    cmp byte ptr [rip + hex_buf + 64], 10
    jne .Lread_key_file_fail

.Lread_key_file_decode:
    mov byte ptr [rip + hex_buf + 64], 0
    lea rdi, [rip + hex_buf]
    mov rsi, r12
    call hex32_decode
    cmp eax, 1
    jne .Lread_key_file_fail
    mov eax, 1
    jmp .Lread_key_file_done

.Lread_key_file_fail:
    xor eax, eax
.Lread_key_file_done:
    pop r13
    pop r12
    pop rbx
    ret

read_artifact_file:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov qword ptr [rip + aead_text_len], 0

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, FILE_READ_FLAGS
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lread_artifact_file_fail

    mov r12, rax

.Lread_artifact_file_loop:
    mov eax, SYS_READ
    mov rdi, r12
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js .Lread_artifact_file_fail_close
    jz .Lread_artifact_file_ok_close

    mov r13, qword ptr [rip + aead_text_len]
    mov rdx, AEAD_OPEN_MAX
    sub rdx, r13
    cmp rax, rdx
    ja .Lread_artifact_file_size_close

    lea rdi, [rip + aead_open_buf]
    add rdi, r13
    lea rsi, [rip + io_buf]
    mov rcx, rax
    rep movsb
    add qword ptr [rip + aead_text_len], rax
    jmp .Lread_artifact_file_loop

.Lread_artifact_file_ok_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    mov eax, 1
    jmp .Lread_artifact_file_done

.Lread_artifact_file_size_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    mov eax, 2
    jmp .Lread_artifact_file_done

.Lread_artifact_file_fail_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall

.Lread_artifact_file_fail:
    xor eax, eax
.Lread_artifact_file_done:
    pop r13
    pop r12
    pop rbx
    ret

open_seal_file_paths:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov qword ptr [rip + seal_file_mode], 0

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, FILE_READ_FLAGS
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lopen_seal_file_input_fail
    mov qword ptr [rip + seal_input_fd], rax

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, r12
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .Lopen_seal_file_output_fail
    mov qword ptr [rip + seal_output_fd], rax
    mov qword ptr [rip + seal_file_mode], 1
    mov eax, 1
    jmp .Lopen_seal_file_done

.Lopen_seal_file_output_fail:
    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_input_fd]
    syscall
    mov eax, 2
    jmp .Lopen_seal_file_done

.Lopen_seal_file_input_fail:
    xor eax, eax
.Lopen_seal_file_done:
    pop r12
    pop rbx
    ret

close_seal_files:
    cmp qword ptr [rip + seal_file_mode], 1
    jne .Lclose_seal_files_done

    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_input_fd]
    syscall
    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_output_fd]
    syscall
    mov qword ptr [rip + seal_file_mode], 0

.Lclose_seal_files_done:
    ret

open_output_file:
    mov eax, SYS_OPENAT
    mov rsi, rdi
    mov rdi, AT_FDCWD
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .Lopen_output_file_fail
    mov qword ptr [rip + seal_output_fd], rax
    mov eax, 1
    ret
.Lopen_output_file_fail:
    xor eax, eax
    ret

write_open_plaintext:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, STDOUT
    xor r14d, r14d

    mov rax, qword ptr [rip + aead_output_path]
    test rax, rax
    jz .Lwrite_open_plaintext_write

    # Create temp in the destination directory; final install happens later.
    mov rdi, qword ptr [rip + aead_output_path]
    call create_open_temp
    test eax, eax
    jz .Lwrite_open_plaintext_fail
    mov r13, qword ptr [rip + open_temp_fd]
    mov r14d, 2   # special flag for temp+rename install

.Lwrite_open_plaintext_write:
    mov rdi, r13
    mov rsi, rbx
    mov rdx, r12
    call write_all
    test eax, eax
    jne .Lwrite_open_plaintext_fail_close

    # close handling
    test r14, r14
    jz .Lwrite_open_plaintext_ok
    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall
    test rax, rax
    js .Lwrite_open_plaintext_fail

    cmp r14, 2
    jne .Lwrite_open_plaintext_ok
    # install temp at final path without overwriting an existing output
    lea rdi, [rip + open_temp_path]
    mov rsi, qword ptr [rip + aead_output_path]
    call rename_noreplace_path
    test eax, eax
    jz .Lwrite_rename_fail
    jmp .Lwrite_open_plaintext_ok

.Lwrite_rename_fail:
    # cleanup temp
    lea rdi, [rip + open_temp_path]
    call unlink_path
    xor eax, eax
    jmp .Lwrite_open_plaintext_done

.Lwrite_open_plaintext_ok:
    mov eax, 1
    jmp .Lwrite_open_plaintext_done

.Lwrite_open_plaintext_fail_close:
    test r14, r14
    jz .Lwrite_open_plaintext_fail
    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall
    cmp r14, 2
    jne .Lwrite_open_plaintext_fail
    lea rdi, [rip + open_temp_path]
    call unlink_path

.Lwrite_open_plaintext_fail:
    xor eax, eax
.Lwrite_open_plaintext_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

unlink_path:
    mov eax, SYS_UNLINK
    # rdi = path
    syscall
    test rax, rax
    js .Lunlink_fail
    mov eax, 1
    ret
.Lunlink_fail:
    xor eax, eax
    ret

rename_noreplace_path:
    mov eax, SYS_RENAMEAT2
    # rdi = oldpath, rsi = newpath
    mov rdx, AT_FDCWD
    mov r10, rsi
    mov rsi, rdi
    mov rdi, AT_FDCWD
    mov r8d, RENAME_NOREPLACE
    syscall
    test rax, rax
    js .Lrename_noreplace_fail
    mov eax, 1
    ret
.Lrename_noreplace_fail:
    xor eax, eax
    ret

create_open_temp:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi                 # final path
    lea r12, [rip + open_temp_path]
    xor r13d, r13d               # len
.copy_path:
    mov al, byte ptr [rbx + r13]
    mov byte ptr [r12 + r13], al
    test al, al
    jz .append_suffix
    inc r13
    cmp r13, 4000
    jb .copy_path
    jmp .create_fail
.append_suffix:
    # append ".tmp."
    mov byte ptr [r12 + r13], '.'
    inc r13
    mov byte ptr [r12 + r13], 't'
    inc r13
    mov byte ptr [r12 + r13], 'm'
    inc r13
    mov byte ptr [r12 + r13], 'p'
    inc r13
    mov byte ptr [r12 + r13], '.'
    inc r13
    # now 8 random bytes -> 16 hex
    sub rsp, 16
    mov rdi, rsp
    mov rsi, 8
    call fill_random
    cmp eax, 1
    jne .create_fail_pop
    mov rdi, rsp                 # src random
    lea rsi, [r12 + r13]         # dst in temp path
    mov edx, 8
    call hex_encode
    add r13, 16
    mov byte ptr [r12 + r13], 0
    add rsp, 16
    # now open exclusively
    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    lea rsi, [rip + open_temp_path]
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .create_fail
    mov qword ptr [rip + open_temp_fd], rax
    mov eax, 1
    jmp .create_done
.create_fail_pop:
    add rsp, 16
.create_fail:
    xor eax, eax
.create_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits
