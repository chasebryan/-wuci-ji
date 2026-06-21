.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_gate_contract_verify
.global run_open_authorized_contract

.extern write_all
.extern exit_process
.extern usage_exit
.extern read_key_file
.extern read_artifact_file
.extern open_parse_loaded_envelope
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern hex_encode
.extern memeq
.extern chacha_key
.extern aead_output_path
.extern aead_text_len
.extern aead_open_buf
.extern io_buf
.extern hex_buf
.extern sha_ctx
.extern digest_buf
.extern frost_scalar_buf
.extern frost_group_commitment
.extern frost_group_public_key
.extern frost_verify_left_x
.extern frost_verify_left_y
.extern frost_verify_right_x
.extern frost_verify_right_y
.extern frost_verify_scaled_x
.extern frost_verify_scaled_y
.extern secp256k1_point_x1
.extern secp256k1_point_y1
.extern secp256k1_point_x2
.extern secp256k1_point_y2
.extern secp256k1_point_rx
.extern secp256k1_point_ry
.extern secp256k1_jacobian_rx
.extern secp256k1_jacobian_ry
.extern secp256k1_jacobian_rz
.extern secp256k1_scalar_a
.extern secp256k1_scalar_b
.extern frost_secp256k1_order_le
.extern frost_secp256k1_h2_dst_prime
.extern frost_secp256k1_h2_dst_prime_len
.extern frost_hash_to_scalar_mem
.extern load_secp256k1_compressed_point_arg
.extern load_secp256k1_scalar_arg
.extern secp256k1_projective_basepoint_mul_limbs
.extern secp256k1_jacobian_to_affine_finite_limbs
.extern secp256k1_public_point_mul_limbs
.extern secp256k1_point_add_limbs
.extern secp256k1_field_equal_limbs
.extern copy_field4

run_gate_contract_verify:
    cmp qword ptr [rsp], 4
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    call read_artifact_file
    cmp eax, 1
    je .Lgate_verify_read_contract
    cmp eax, 2
    je gate_contract_file_error
    jmp gate_artifact_file_error

.Lgate_verify_read_contract:
    mov rdi, qword ptr [rsp + 32]
    call gate_read_contract_file
    cmp eax, 1
    je .Lgate_verify_loaded
    jmp gate_contract_file_error

.Lgate_verify_loaded:
    call gate_verify_loaded_contract
    cmp eax, 1
    jne gate_contract_error

    mov rdi, STDOUT
    lea rsi, [rip + gate_valid_msg]
    mov edx, OFFSET FLAT:gate_valid_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

run_open_authorized_contract:
    cmp qword ptr [rsp], 6
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne gate_keyfile_error

    mov rax, qword ptr [rsp + 48]
    mov qword ptr [rip + aead_output_path], rax

    mov rdi, qword ptr [rsp + 32]
    call read_artifact_file
    cmp eax, 1
    je .Lopen_authorized_read_contract
    cmp eax, 2
    je gate_contract_file_error
    jmp gate_artifact_file_error

.Lopen_authorized_read_contract:
    mov rdi, qword ptr [rsp + 40]
    call gate_read_contract_file
    cmp eax, 1
    jne gate_contract_file_error

    call gate_verify_loaded_contract
    cmp eax, 1
    jne gate_contract_error

    jmp open_parse_loaded_envelope

gate_verify_loaded_contract:
    call gate_parse_contract
    cmp eax, 1
    jne .Lgate_verify_fail

    call gate_build_manifest
    cmp eax, 1
    jne .Lgate_verify_fail

    lea rdi, [rip + gate_manifest_buf]
    mov rsi, qword ptr [rip + gate_manifest_len]
    lea rdx, [rip + digest_buf]
    call gate_sha256_to_digest
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + gate_artifact_manifest_sha256]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_verify_fail

    call gate_build_warrant
    cmp eax, 1
    jne .Lgate_verify_fail

    call gate_compute_challenge
    cmp eax, 1
    jne .Lgate_verify_fail

    call gate_verify_signature
    cmp eax, 1
    jne .Lgate_verify_fail

    mov eax, 1
    ret

.Lgate_verify_fail:
    xor eax, eax
    ret

gate_read_contract_file:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov qword ptr [rip + gate_contract_len], 0

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lgate_read_contract_fail

    mov r12, rax

.Lgate_read_contract_loop:
    mov eax, SYS_READ
    mov rdi, r12
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js .Lgate_read_contract_fail_close
    jz .Lgate_read_contract_ok_close

    mov r13, qword ptr [rip + gate_contract_len]
    mov rdx, GATE_CONTRACT_MAX
    sub rdx, r13
    cmp rax, rdx
    ja .Lgate_read_contract_size_close

    lea rdi, [rip + gate_contract_buf]
    add rdi, r13
    lea rsi, [rip + io_buf]
    mov rcx, rax
    rep movsb
    add qword ptr [rip + gate_contract_len], rax
    jmp .Lgate_read_contract_loop

.Lgate_read_contract_ok_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    lea rdi, [rip + gate_contract_buf]
    add rdi, qword ptr [rip + gate_contract_len]
    mov byte ptr [rdi], 0
    mov eax, 1
    jmp .Lgate_read_contract_done

.Lgate_read_contract_size_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    mov eax, 2
    jmp .Lgate_read_contract_done

.Lgate_read_contract_fail_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall

.Lgate_read_contract_fail:
    xor eax, eax

.Lgate_read_contract_done:
    pop r13
    pop r12
    pop rbx
    ret

gate_parse_contract:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, qword ptr [rip + gate_contract_len]
    test r12, r12
    jz .Lgate_parse_fail

    lea rbx, [rip + gate_contract_buf]
    mov r13, rbx
    mov r14, r12

.Lgate_parse_ascii_loop:
    mov al, byte ptr [r13]
    cmp al, 0x7f
    ja .Lgate_parse_fail
    cmp al, 13
    je .Lgate_parse_fail
    inc r13
    dec r14
    jne .Lgate_parse_ascii_loop

    lea r13, [rbx + r12 - 1]
    cmp byte ptr [r13], 10
    jne .Lgate_parse_fail
    cmp r12, 2
    jb .Lgate_parse_fail
    cmp byte ptr [r13 - 1], 10
    je .Lgate_parse_fail

    mov qword ptr [rip + gate_parse_ptr], rbx
    lea rax, [rbx + r12]
    mov qword ptr [rip + gate_parse_end], rax

    lea rdi, [rip + gate_schema_line]
    mov esi, OFFSET FLAT:gate_schema_line_len
    call gate_consume_literal
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_action_open_line]
    mov esi, OFFSET FLAT:gate_action_open_line_len
    call gate_consume_literal
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_artifact_sha256_label]
    mov esi, OFFSET FLAT:gate_artifact_sha256_label_len
    mov edx, 32
    lea rcx, [rip + gate_artifact_sha256]
    xor r8d, r8d
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_authorization_message_sha256_label]
    mov esi, OFFSET FLAT:gate_authorization_message_sha256_label_len
    mov edx, 32
    lea rcx, [rip + gate_authorization_message_sha256]
    xor r8d, r8d
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_receipt_sha256_label]
    mov esi, OFFSET FLAT:gate_receipt_sha256_label_len
    mov edx, 32
    lea rcx, [rip + gate_receipt_sha256]
    xor r8d, r8d
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_artifact_manifest_sha256_label]
    mov esi, OFFSET FLAT:gate_artifact_manifest_sha256_label_len
    mov edx, 32
    lea rcx, [rip + gate_artifact_manifest_sha256]
    xor r8d, r8d
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_group_public_key_label]
    mov esi, OFFSET FLAT:gate_group_public_key_label_len
    mov edx, 33
    lea rcx, [rip + gate_group_public_key]
    lea r8, [rip + gate_group_public_key_hex_ptr]
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_group_commitment_label]
    mov esi, OFFSET FLAT:gate_group_commitment_label_len
    mov edx, 33
    lea rcx, [rip + gate_group_commitment]
    lea r8, [rip + gate_group_commitment_hex_ptr]
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_challenge_label]
    mov esi, OFFSET FLAT:gate_challenge_label_len
    mov edx, 32
    lea rcx, [rip + gate_challenge]
    lea r8, [rip + gate_challenge_hex_ptr]
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_signature_commitment_label]
    mov esi, OFFSET FLAT:gate_signature_commitment_label_len
    mov edx, 33
    lea rcx, [rip + gate_signature_commitment]
    lea r8, [rip + gate_signature_commitment_hex_ptr]
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_signature_scalar_label]
    mov esi, OFFSET FLAT:gate_signature_scalar_label_len
    mov edx, 32
    lea rcx, [rip + gate_signature_scalar]
    lea r8, [rip + gate_signature_scalar_hex_ptr]
    call gate_consume_hex_line
    cmp eax, 1
    jne .Lgate_parse_fail

    mov rax, qword ptr [rip + gate_parse_ptr]
    cmp rax, qword ptr [rip + gate_parse_end]
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_group_public_key]
    call gate_check_compressed_point
    cmp eax, 1
    jne .Lgate_parse_fail
    lea rdi, [rip + gate_group_commitment]
    call gate_check_compressed_point
    cmp eax, 1
    jne .Lgate_parse_fail
    lea rdi, [rip + gate_signature_commitment]
    call gate_check_compressed_point
    cmp eax, 1
    jne .Lgate_parse_fail

    lea rdi, [rip + gate_signature_commitment]
    lea rsi, [rip + gate_group_commitment]
    mov edx, 33
    call memeq
    cmp eax, 1
    jne .Lgate_parse_fail

    mov eax, 1
    jmp .Lgate_parse_done

.Lgate_parse_fail:
    xor eax, eax

.Lgate_parse_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

gate_consume_literal:
    push rbx
    push r12
    push r13
    mov r13, rdi
    mov r12, rsi
    mov rbx, qword ptr [rip + gate_parse_ptr]
    mov rax, qword ptr [rip + gate_parse_end]
    sub rax, rbx
    cmp rax, r12
    jb .Lgate_consume_literal_fail
    mov rdi, rbx
    mov rsi, r13
    mov rdx, r12
    call memeq
    cmp eax, 1
    jne .Lgate_consume_literal_fail
    add rbx, r12
    mov qword ptr [rip + gate_parse_ptr], rbx
    mov eax, 1
    jmp .Lgate_consume_literal_done

.Lgate_consume_literal_fail:
    xor eax, eax

.Lgate_consume_literal_done:
    pop r13
    pop r12
    pop rbx
    ret

gate_consume_hex_line:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbp, r8
    mov r12, rdx
    mov r13, rcx
    call gate_consume_literal
    cmp eax, 1
    jne .Lgate_consume_hex_fail

    mov rbx, qword ptr [rip + gate_parse_ptr]
    test rbp, rbp
    jz .Lgate_consume_hex_no_store
    mov qword ptr [rbp], rbx

.Lgate_consume_hex_no_store:
    lea r14, [r12 + r12]
    mov rax, qword ptr [rip + gate_parse_end]
    sub rax, rbx
    lea r15, [r14 + 1]
    cmp rax, r15
    jb .Lgate_consume_hex_fail

    lea r15, [rbx + r14]
    cmp byte ptr [r15], 10
    jne .Lgate_consume_hex_fail
    mov byte ptr [r15], 0

    test r12, r12
    jz .Lgate_consume_hex_decoded

.Lgate_consume_hex_loop:
    movzx eax, byte ptr [rbx]
    call gate_hex_nibble_lower
    cmp eax, 0
    jl .Lgate_consume_hex_fail
    shl al, 4
    mov r10b, al
    movzx eax, byte ptr [rbx + 1]
    call gate_hex_nibble_lower
    cmp eax, 0
    jl .Lgate_consume_hex_fail
    or al, r10b
    mov byte ptr [r13], al
    add rbx, 2
    inc r13
    dec r12
    jne .Lgate_consume_hex_loop

.Lgate_consume_hex_decoded:
    lea rax, [r15 + 1]
    mov qword ptr [rip + gate_parse_ptr], rax
    mov eax, 1
    jmp .Lgate_consume_hex_done

.Lgate_consume_hex_fail:
    xor eax, eax

.Lgate_consume_hex_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

gate_hex_nibble_lower:
    cmp al, '0'
    jb .Lgate_hex_nibble_fail
    cmp al, '9'
    jbe .Lgate_hex_nibble_digit
    cmp al, 'a'
    jb .Lgate_hex_nibble_fail
    cmp al, 'f'
    ja .Lgate_hex_nibble_fail
    sub al, 'a' - 10
    movzx eax, al
    ret

.Lgate_hex_nibble_digit:
    sub al, '0'
    movzx eax, al
    ret

.Lgate_hex_nibble_fail:
    mov eax, -1
    ret

gate_check_compressed_point:
    mov al, byte ptr [rdi]
    cmp al, 2
    je .Lgate_check_compressed_ok
    cmp al, 3
    je .Lgate_check_compressed_ok
    xor eax, eax
    ret

.Lgate_check_compressed_ok:
    mov eax, 1
    ret

gate_build_manifest:
    push rbx
    lea rax, [rip + gate_manifest_buf]
    mov qword ptr [rip + gate_append_ptr], rax
    lea rax, [rip + gate_manifest_buf + GATE_MANIFEST_MAX]
    mov qword ptr [rip + gate_append_end], rax

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_MIN_LEN
    jb .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + gate_envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lgate_manifest_v1

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V2_MIN_LEN
    jb .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + gate_envelope_v2_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lgate_manifest_v2

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V3_MIN_LEN
    jb .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + gate_envelope_v3_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lgate_manifest_v3
    jmp .Lgate_manifest_fail

.Lgate_manifest_v1:
    lea rdi, [rip + gate_manifest_v1_msg]
    mov esi, OFFSET FLAT:gate_manifest_v1_msg_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + gate_artifact_sha256]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_length_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_length_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_MIN_LEN
    call gate_append_u64_decimal_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_MIN_LEN
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_nonce_label]
    mov esi, OFFSET FLAT:gate_manifest_nonce_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    mov esi, ENVELOPE_NONCE_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_tag_label]
    mov esi, OFFSET FLAT:gate_manifest_tag_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    mov esi, ENVELOPE_TAG_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail
    jmp .Lgate_manifest_done

.Lgate_manifest_v2:
    lea rdi, [rip + gate_manifest_v2_msg]
    mov esi, OFFSET FLAT:gate_manifest_v2_msg_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_key_id_label]
    mov esi, OFFSET FLAT:gate_manifest_key_id_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    mov esi, ENVELOPE_KEY_ID_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + gate_artifact_sha256]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_length_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_length_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_V2_MIN_LEN
    call gate_append_u64_decimal_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_V2_MIN_LEN
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_nonce_label]
    mov esi, OFFSET FLAT:gate_manifest_nonce_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_KEY_ID_LEN]
    mov esi, ENVELOPE_NONCE_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_tag_label]
    mov esi, OFFSET FLAT:gate_manifest_tag_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    mov esi, ENVELOPE_TAG_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail
    jmp .Lgate_manifest_done

.Lgate_manifest_v3:
    lea rdi, [rip + gate_manifest_v3_msg]
    mov esi, OFFSET FLAT:gate_manifest_v3_msg_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ephemeral_public_label]
    mov esi, OFFSET FLAT:gate_manifest_ephemeral_public_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    mov esi, ENVELOPE_X25519_PUBLIC_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_key_id_label]
    mov esi, OFFSET FLAT:gate_manifest_key_id_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN]
    mov esi, ENVELOPE_KEY_ID_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + gate_artifact_sha256]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_length_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_length_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_V3_MIN_LEN
    call gate_append_u64_decimal_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:gate_manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_V3_MIN_LEN
    call gate_append_labeled_sha256
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_nonce_label]
    mov esi, OFFSET FLAT:gate_manifest_nonce_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN + ENVELOPE_KEY_ID_LEN]
    mov esi, ENVELOPE_NONCE_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

    lea rdi, [rip + gate_manifest_tag_label]
    mov esi, OFFSET FLAT:gate_manifest_tag_label_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_manifest_fail
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    mov esi, ENVELOPE_TAG_LEN
    call gate_append_hex_newline
    cmp eax, 1
    jne .Lgate_manifest_fail

.Lgate_manifest_done:
    mov rax, qword ptr [rip + gate_append_ptr]
    lea rdx, [rip + gate_manifest_buf]
    sub rax, rdx
    mov qword ptr [rip + gate_manifest_len], rax
    mov eax, 1
    jmp .Lgate_manifest_return

.Lgate_manifest_fail:
    xor eax, eax

.Lgate_manifest_return:
    pop rbx
    ret

gate_build_warrant:
    lea rax, [rip + gate_warrant_buf]
    mov qword ptr [rip + gate_append_ptr], rax
    lea rax, [rip + gate_warrant_buf + GATE_WARRANT_MAX]
    mov qword ptr [rip + gate_append_end], rax

    lea rdi, [rip + gate_warrant_message_prefix]
    mov esi, OFFSET FLAT:gate_warrant_message_prefix_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_warrant_fail

    lea rdi, [rip + gate_action_open_value]
    mov esi, OFFSET FLAT:gate_action_open_value_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_warrant_fail

    lea rdi, [rip + gate_warrant_message_manifest_prefix]
    mov esi, OFFSET FLAT:gate_warrant_message_manifest_prefix_len
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_warrant_fail

    lea rdi, [rip + gate_manifest_buf]
    mov rsi, qword ptr [rip + gate_manifest_len]
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_warrant_fail

    mov rax, qword ptr [rip + gate_append_ptr]
    lea rdx, [rip + gate_warrant_buf]
    sub rax, rdx
    mov qword ptr [rip + gate_warrant_len], rax

    lea rdi, [rip + gate_warrant_buf]
    mov rsi, qword ptr [rip + gate_warrant_len]
    lea rdx, [rip + digest_buf]
    call gate_sha256_to_digest
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + gate_authorization_message_sha256]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_warrant_fail
    mov eax, 1
    ret

.Lgate_warrant_fail:
    xor eax, eax
    ret

gate_compute_challenge:
    push rbx
    mov rbx, qword ptr [rip + gate_warrant_len]
    add rbx, 66
    cmp rbx, GATE_CHALLENGE_INPUT_MAX
    ja .Lgate_challenge_fail

    lea rdi, [rip + gate_challenge_input]
    lea rsi, [rip + gate_group_commitment]
    mov ecx, 33
    rep movsb
    lea rsi, [rip + gate_group_public_key]
    mov ecx, 33
    rep movsb
    lea rsi, [rip + gate_warrant_buf]
    mov rcx, qword ptr [rip + gate_warrant_len]
    rep movsb

    lea rdi, [rip + frost_secp256k1_h2_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h2_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    lea rcx, [rip + gate_challenge_input]
    mov r8, rbx
    lea r9, [rip + frost_scalar_buf]
    call frost_hash_to_scalar_mem

    lea rdi, [rip + frost_scalar_buf]
    lea rsi, [rip + gate_challenge]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lgate_challenge_fail
    mov eax, 1
    jmp .Lgate_challenge_done

.Lgate_challenge_fail:
    xor eax, eax

.Lgate_challenge_done:
    pop rbx
    ret

gate_verify_signature:
    mov rdi, qword ptr [rip + gate_signature_commitment_hex_ptr]
    lea rsi, [rip + frost_group_commitment]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne .Lgate_signature_fail

    mov rdi, qword ptr [rip + gate_group_public_key_hex_ptr]
    lea rsi, [rip + frost_group_public_key]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne .Lgate_signature_fail

    mov rdi, qword ptr [rip + gate_signature_scalar_hex_ptr]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne .Lgate_signature_fail

    mov rdi, qword ptr [rip + gate_challenge_hex_ptr]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne .Lgate_signature_fail

    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_projective_basepoint_mul_limbs
    cmp eax, 1
    jne .Lgate_signature_fail
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_rz]
    lea rcx, [rip + frost_verify_left_x]
    lea r8, [rip + frost_verify_left_y]
    call secp256k1_jacobian_to_affine_finite_limbs

    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_point_x2]
    lea rdx, [rip + secp256k1_point_y2]
    lea rcx, [rip + frost_verify_scaled_x]
    lea r8, [rip + frost_verify_scaled_y]
    call secp256k1_public_point_mul_limbs
    cmp eax, 1
    jne .Lgate_signature_right_is_r

    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    lea rdx, [rip + frost_verify_scaled_x]
    lea rcx, [rip + frost_verify_scaled_y]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne .Lgate_signature_fail
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + frost_verify_right_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + frost_verify_right_y]
    call copy_field4
    jmp .Lgate_signature_compare

.Lgate_signature_right_is_r:
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + frost_verify_right_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_y1]
    lea rsi, [rip + frost_verify_right_y]
    call copy_field4

.Lgate_signature_compare:
    lea rdi, [rip + frost_verify_left_x]
    lea rsi, [rip + frost_verify_right_x]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne .Lgate_signature_fail
    lea rdi, [rip + frost_verify_left_y]
    lea rsi, [rip + frost_verify_right_y]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne .Lgate_signature_fail
    mov eax, 1
    ret

.Lgate_signature_fail:
    xor eax, eax
    ret

gate_append_labeled_sha256:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov rdi, rbx
    mov rsi, r12
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_append_labeled_sha256_fail
    mov rdi, r13
    mov rsi, r14
    lea rdx, [rip + digest_buf]
    call gate_sha256_to_digest
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    lea rdi, [rip + hex_buf]
    mov esi, 65
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_append_labeled_sha256_fail
    mov eax, 1
    jmp .Lgate_append_labeled_sha256_done

.Lgate_append_labeled_sha256_fail:
    xor eax, eax

.Lgate_append_labeled_sha256_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

gate_sha256_to_digest:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, r13
    call sha256_final
    pop r13
    pop r12
    pop rbx
    ret

gate_append_hex_newline:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov rdi, rbx
    lea rsi, [rip + hex_buf]
    mov rdx, r12
    call hex_encode
    lea rax, [r12 + r12]
    lea rdx, [rip + hex_buf]
    mov byte ptr [rdx + rax], 10
    inc rax
    lea rdi, [rip + hex_buf]
    mov rsi, rax
    call gate_append_bytes
    pop r12
    pop rbx
    ret

gate_append_u64_decimal_newline:
    push rbx
    push r12
    push r13
    mov rax, rdi
    lea rbx, [rip + hex_buf + 32]
    xor r12d, r12d
    test rax, rax
    jne .Lgate_decimal_loop
    dec rbx
    mov byte ptr [rbx], '0'
    mov r12d, 1
    jmp .Lgate_decimal_append

.Lgate_decimal_loop:
    xor edx, edx
    mov r13, 10
    div r13
    add dl, '0'
    dec rbx
    mov byte ptr [rbx], dl
    inc r12
    test rax, rax
    jne .Lgate_decimal_loop

.Lgate_decimal_append:
    mov rdi, rbx
    mov rsi, r12
    call gate_append_bytes
    cmp eax, 1
    jne .Lgate_decimal_done
    lea rdi, [rip + gate_newline]
    mov esi, 1
    call gate_append_bytes

.Lgate_decimal_done:
    pop r13
    pop r12
    pop rbx
    ret

gate_append_bytes:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov rdi, qword ptr [rip + gate_append_ptr]
    mov r13, qword ptr [rip + gate_append_end]
    mov rax, r13
    sub rax, rdi
    cmp r12, rax
    ja .Lgate_append_fail
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    mov qword ptr [rip + gate_append_ptr], rdi
    mov eax, 1
    jmp .Lgate_append_done

.Lgate_append_fail:
    xor eax, eax

.Lgate_append_done:
    pop r13
    pop r12
    pop rbx
    ret

gate_artifact_file_error:
    mov rdi, STDERR
    lea rsi, [rip + gate_artifact_file_error_msg]
    mov edx, OFFSET FLAT:gate_artifact_file_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

gate_contract_file_error:
    mov rdi, STDERR
    lea rsi, [rip + gate_contract_file_error_msg]
    mov edx, OFFSET FLAT:gate_contract_file_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

gate_keyfile_error:
    mov rdi, STDERR
    lea rsi, [rip + gate_keyfile_error_msg]
    mov edx, OFFSET FLAT:gate_keyfile_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

gate_contract_error:
    mov rdi, STDERR
    lea rsi, [rip + gate_contract_error_msg]
    mov edx, OFFSET FLAT:gate_contract_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

.section .rodata
gate_valid_msg:
    .ascii "valid\n"
.set gate_valid_msg_len, . - gate_valid_msg

gate_artifact_file_error_msg:
    .ascii "wuci-ji: artifact file could not be read\n"
.set gate_artifact_file_error_msg_len, . - gate_artifact_file_error_msg

gate_contract_file_error_msg:
    .ascii "wuci-ji: contract file could not be read\n"
.set gate_contract_file_error_msg_len, . - gate_contract_file_error_msg

gate_keyfile_error_msg:
    .ascii "wuci-ji: keyfile could not be read\n"
.set gate_keyfile_error_msg_len, . - gate_keyfile_error_msg

gate_contract_error_msg:
    .ascii "wuci-ji: gate contract verification failed\n"
.set gate_contract_error_msg_len, . - gate_contract_error_msg

gate_newline:
    .ascii "\n"

gate_schema_line:
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
.set gate_schema_line_len, . - gate_schema_line

gate_action_open_line:
    .ascii "action: open\n"
.set gate_action_open_line_len, . - gate_action_open_line

gate_action_open_value:
    .ascii "open"
.set gate_action_open_value_len, . - gate_action_open_value

gate_artifact_sha256_label:
    .ascii "artifact-sha256: "
.set gate_artifact_sha256_label_len, . - gate_artifact_sha256_label

gate_authorization_message_sha256_label:
    .ascii "authorization-message-sha256: "
.set gate_authorization_message_sha256_label_len, . - gate_authorization_message_sha256_label

gate_receipt_sha256_label:
    .ascii "receipt-sha256: "
.set gate_receipt_sha256_label_len, . - gate_receipt_sha256_label

gate_artifact_manifest_sha256_label:
    .ascii "artifact-manifest-sha256: "
.set gate_artifact_manifest_sha256_label_len, . - gate_artifact_manifest_sha256_label

gate_group_public_key_label:
    .ascii "group-public-key: "
.set gate_group_public_key_label_len, . - gate_group_public_key_label

gate_group_commitment_label:
    .ascii "group-commitment: "
.set gate_group_commitment_label_len, . - gate_group_commitment_label

gate_challenge_label:
    .ascii "challenge: "
.set gate_challenge_label_len, . - gate_challenge_label

gate_signature_commitment_label:
    .ascii "signature-commitment: "
.set gate_signature_commitment_label_len, . - gate_signature_commitment_label

gate_signature_scalar_label:
    .ascii "signature-scalar: "
.set gate_signature_scalar_label_len, . - gate_signature_scalar_label

gate_envelope_prefix:
    .ascii "WJSEAL"
    .byte 0x01, 0x01

gate_envelope_v2_prefix:
    .ascii "WJSEAL"
    .byte 0x02, 0x01

gate_envelope_v3_prefix:
    .ascii "WJSEAL"
    .byte 0x03, 0x01

gate_manifest_ephemeral_public_label:
    .ascii "ephemeral-public: "
.set gate_manifest_ephemeral_public_label_len, . - gate_manifest_ephemeral_public_label

gate_manifest_key_id_label:
    .ascii "key-id: "
.set gate_manifest_key_id_label_len, . - gate_manifest_key_id_label

gate_manifest_nonce_label:
    .ascii "nonce: "
.set gate_manifest_nonce_label_len, . - gate_manifest_nonce_label

gate_manifest_v1_msg:
    .ascii "version: 1\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 20\n"
.set gate_manifest_v1_msg_len, . - gate_manifest_v1_msg

gate_manifest_v2_msg:
    .ascii "version: 2\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 36\n"
.set gate_manifest_v2_msg_len, . - gate_manifest_v2_msg

gate_manifest_v3_msg:
    .ascii "version: 3\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 68\n"
.set gate_manifest_v3_msg_len, . - gate_manifest_v3_msg

gate_manifest_ciphertext_length_label:
    .ascii "ciphertext-length: "
.set gate_manifest_ciphertext_length_label_len, . - gate_manifest_ciphertext_length_label

gate_manifest_artifact_sha256_label:
    .ascii "artifact-sha256: "
.set gate_manifest_artifact_sha256_label_len, . - gate_manifest_artifact_sha256_label

gate_manifest_ciphertext_sha256_label:
    .ascii "ciphertext-sha256: "
.set gate_manifest_ciphertext_sha256_label_len, . - gate_manifest_ciphertext_sha256_label

gate_manifest_tag_label:
    .ascii "tag: "
.set gate_manifest_tag_label_len, . - gate_manifest_tag_label

gate_warrant_message_prefix:
    .ascii "schema: wuci-frost-authorization-message-v1\n"
    .ascii "suite: FROST-secp256k1-SHA256-v1\n"
    .ascii "production: false\n"
    .ascii "action: "
.set gate_warrant_message_prefix_len, . - gate_warrant_message_prefix

gate_warrant_message_manifest_prefix:
    .ascii "\nartifact-manifest:\n"
.set gate_warrant_message_manifest_prefix_len, . - gate_warrant_message_manifest_prefix

.section .bss
.align 16
gate_contract_buf:
    .skip GATE_CONTRACT_MAX + 1
.align 8
gate_contract_len:
    .skip 8
.align 8
gate_parse_ptr:
    .skip 8
.align 8
gate_parse_end:
    .skip 8
.align 16
gate_manifest_buf:
    .skip GATE_MANIFEST_MAX
.align 8
gate_manifest_len:
    .skip 8
.align 16
gate_warrant_buf:
    .skip GATE_WARRANT_MAX
.align 8
gate_warrant_len:
    .skip 8
.align 16
gate_challenge_input:
    .skip GATE_CHALLENGE_INPUT_MAX
.align 8
gate_append_ptr:
    .skip 8
.align 8
gate_append_end:
    .skip 8
.align 16
gate_artifact_sha256:
    .skip 32
.align 16
gate_authorization_message_sha256:
    .skip 32
.align 16
gate_receipt_sha256:
    .skip 32
.align 16
gate_artifact_manifest_sha256:
    .skip 32
.align 16
gate_group_public_key:
    .skip 33
.align 16
gate_group_commitment:
    .skip 33
.align 16
gate_challenge:
    .skip 32
.align 16
gate_signature_commitment:
    .skip 33
.align 16
gate_signature_scalar:
    .skip 32
.align 8
gate_group_public_key_hex_ptr:
    .skip 8
.align 8
gate_group_commitment_hex_ptr:
    .skip 8
.align 8
gate_challenge_hex_ptr:
    .skip 8
.align 8
gate_signature_commitment_hex_ptr:
    .skip 8
.align 8
gate_signature_scalar_hex_ptr:
    .skip 8

.section .note.GNU-stack,"",@progbits
