; main.asm - x86 Assembly for Aerospace Encryption Program
; Designed for Windows, runs from USB, uses RAM only, clears registers and memory

%include "win32n.inc"  ; Windows API constants

; External C library and mbedTLS functions
extern _fgets
extern _printf
extern _strlen
extern _memset
extern _mbedtls_aes_init
extern _mbedtls_aes_setkey_enc
extern _mbedtls_aes_crypt_cbc
extern _mbedtls_aes_free

; Data section: Constants and strings
section .data
    welcome db "Pico Message Gadget", 10, 0
    prompt_msg db "Enter characters including spaces: ", 0
    prompt_key db "Enter 32 capital hex letters (secret key): ", 0
    prompt_iv db "Enter 32 capital hex letters (IV, PKCS7 padding): ", 0
    error_msg db "Error: Message too long.", 10, 0
    error_key db "Error: Invalid key.", 10, 0
    error_iv db "Error: Invalid IV.", 10, 0
    error_pad db "Error: Padding failed.", 10, 0
    error_keyset db "Error: Failed to set key.", 10, 0
    keys_erased db "Keys will be erased from RAM when the program exits.", 10, 0

; BSS section: Uninitialized buffers
section .bss
    message resb 256          ; char message[MAX_MESSAGE_LEN]
    key_hex resb 33           ; char key_hex[33]
    iv_hex resb 33            ; char iv_hex[33]
    key resb 16               ; unsigned char key[16]
    iv resb 16                ; unsigned char iv[16]
    padded resb 272           ; unsigned char padded[MAX_MESSAGE_LEN + 16]
    cipher resb 272           ; unsigned char cipher[MAX_MESSAGE_LEN + 16]
    hex_output resb 545       ; char hex_output[(MAX_MESSAGE_LEN + 16) * 2 + 1]
    aes_ctx resb 256          ; mbedtls_aes_context aes (size approximate)

; Code section
section .text
global _main

_main:
    ; C++: int main() {
    ; Setup stack frame (equivalent to function prologue in C++)
    push ebp
    mov ebp, esp

    ; C++: if (!self_test()) { printf("Self-test failed!\n"); return 1; }
    ; Call self_test (implementation omitted here, similar structure)
    call self_test
    test eax, eax
    jnz .self_test_pass
    push error_self_test    ; Assume defined in .data
    call _printf
    add esp, 4
    mov eax, 1
    jmp .exit

.self_test_pass:
    ; C++: printf("Pico Message Gadget\n");
    ; Print welcome message using C printf
    push welcome
    call _printf
    add esp, 4              ; Clean up stack (stdcall convention)

    ; C++: printf("Enter characters including spaces: "); int msg_len = read_line(message, MAX_MESSAGE_LEN);
    push prompt_msg
    call _printf
    add esp, 4
    push 256                ; max_len
    push message            ; buffer
    push dword [stdin]      ; stdin (defined in win32n.inc or link with msvcrt)
    call _fgets
    add esp, 12
    test eax, eax
    jz .error_message       ; If fgets fails or buffer overflows

    ; C++: if (msg_len == 0) { printf("Error: Message too long.\n"); return 1; }
    push message
    call _strlen
    add esp, 4
    test eax, eax
    jnz .msg_ok
.error_message:
    push error_msg
    call _printf
    add esp, 4
    mov eax, 1
    jmp .exit

.msg_ok:
    mov ebx, eax            ; Save msg_len in ebx

    ; C++: printf("Enter 32 capital hex letters (secret key): ");
    ;       if (read_line(key_hex, 33) != 32 || !hex_to_bytes(key_hex, key, 16)) { ... }
    push prompt_key
    call _printf
    add esp, 4
    push 33
    push key_hex
    push dword [stdin]
    call _fgets
    add esp, 12
    push key_hex
    call _strlen
    add esp, 4
    cmp eax, 32
    jne .error_key
    push 16
    push key
    push key_hex
    call hex_to_bytes       ; See implementation below
    add esp, 12
    test eax, eax
    jz .error_key
    jmp .key_ok
.error_key:
    push error_key
    call _printf
    add esp, 4
    mov eax, 1
    jmp .exit

.key_ok:
    ; C++: printf("Enter 32 capital hex letters (IV, PKCS7 padding): ");
    ;       if (read_line(iv_hex, 33) != 32 || !hex_to_bytes(iv_hex, iv, 16)) { ... }
    push prompt_iv
    call _printf
    add esp, 4
    push 33
    push iv_hex
    push dword [stdin]
    call _fgets
    add esp, 12
    push iv_hex
    call _strlen
    add esp, 4
    cmp eax, 32
    jne .error_iv
    push 16
    push iv
    push iv_hex
    call hex_to_bytes
    add esp, 12
    test eax, eax
    jz .error_iv
    jmp .iv_ok
.error_iv:
    push error_iv
    call _printf
    add esp, 4
    mov eax, 1
    jmp .exit

.iv_ok:
    ; C++: int padded_len = pkcs7_pad(message, msg_len, padded, MAX_MESSAGE_LEN + 16);
    push 272                ; max_len
    push padded             ; output
    push message            ; input
    push ebx                ; input_len (msg_len)
    call pkcs7_pad          ; To be implemented
    add esp, 16
    test eax, eax
    jz .error_padding
    mov ecx, eax            ; Save padded_len in ecx
    jmp .pad_ok
.error_padding:
    push error_pad
    call _printf
    add esp, 4
    mov eax, 1
    jmp .exit

.pad_ok:
    ; C++: mbedtls_aes_init(&aes);
    push aes_ctx
    call _mbedtls_aes_init
    add esp, 4

    ; C++: if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) { ... }
    push 128                ; keybits
    push key                ; key
    push aes_ctx            ; context
    call _mbedtls_aes_setkey_enc
    add esp, 12
    test eax, eax
    jz .keyset_ok
    push error_keyset
    call _printf
    add esp, 4
    call _mbedtls_aes_free
    mov eax, 1
    jmp .exit

.keyset_ok:
    ; C++: mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded, cipher);
    push cipher             ; output
    push padded             ; input
    push iv                 ; iv
    push ecx                ; length (padded_len)
    push 1                  ; MBEDTLS_AES_ENCRYPT
    push aes_ctx            ; context
    call _mbedtls_aes_crypt_cbc
    add esp, 24

    ; C++: mbedtls_aes_free(&aes);
    push aes_ctx
    call _mbedtls_aes_free
    add esp, 4

    ; C++: bytes_to_hex(cipher, padded_len, hex_output);
    push hex_output
    push ecx                ; padded_len
    push cipher
    call bytes_to_hex       ; To be implemented
    add esp, 12

    ; C++: print_formatted_hex(hex_output);
    push hex_output
    call print_formatted_hex ; To be implemented
    add esp, 4

    ; C++: printf("Keys will be erased from RAM when the program exits.\n");
    push keys_erased
    call _printf
    add esp, 4

    ; C++: memset(key, 0, 16); memset(iv, 0, 16); etc.
    ; Explicitly clear sensitive memory
    push 16
    push 0
    push key
    call _memset
    add esp, 12
    push 16
    push 0
    push iv
    call _memset
    add esp, 12
    push 272
    push 0
    push padded
    call _memset
    add esp, 12
    push 272
    push 0
    push cipher
    call _memset
    add esp, 12

    ; Clear all registers explicitly
    xor eax, eax            ; Clear EAX
    xor ebx, ebx            ; Clear EBX (held msg_len)
    xor ecx, ecx            ; Clear ECX (held padded_len)
    xor edx, edx            ; Clear EDX
    xor esi, esi            ; Clear ESI
    xor edi, edi            ; Clear EDI

    ; C++: return 0;
    mov eax, 0              ; Return code 0
.exit:
    pop ebp                 ; Restore stack frame
    ret

; C++: int hex_to_bytes(const char *hex, unsigned char *bytes, int byte_len) {
hex_to_bytes:
    push ebp
    mov ebp, esp
    push ebx                ; Save registers
    push esi
    push edi

    ; Stack: [ebp+16] = byte_len, [ebp+12] = bytes, [ebp+8] = hex
    mov esi, [ebp+8]        ; hex pointer
    mov edi, [ebp+12]       ; bytes pointer
    mov ecx, [ebp+16]       ; byte_len
    shl ecx, 1              ; ecx = byte_len * 2 (hex chars)

    ; C++: for (int i = 0; i < byte_len * 2; i++) { if (!isxdigit(hex[i])) return 0; }
    xor ebx, ebx            ; i = 0
.check_loop:
    cmp ebx, ecx
    jge .check_done
    movzx eax, byte [esi + ebx]
    call isxdigit           ; To be implemented or use C lib
    test eax, eax
    jz .fail
    inc ebx
    jmp .check_loop
.check_done:

    ; C++: for (int i = 0; i < byte_len; i++) { sscanf(hex + i * 2, "%2hhx", &bytes[i]); }
    xor ebx, ebx            ; i = 0
    mov ecx, [ebp+16]       ; byte_len
.convert_loop:
    cmp ebx, ecx
    jge .success
    ; Simplified: Assume hex pair to byte conversion (e.g., "4A" -> 0x4A)
    movzx eax, byte [esi]   ; High nibble
    sub al, '0'
    cmp al, 9
    jle .high_num
    sub al, 7               ; 'A'-'0'-10
.high_num:
    shl al, 4               ; Shift to high nibble
    movzx edx, byte [esi+1] ; Low nibble
    sub dl, '0'
    cmp dl, 9
    jle .low_num
    sub dl, 7
.low_num:
    or al, dl               ; Combine nibbles
    mov [edi + ebx], al     ; Store byte
    add esi, 2              ; Next hex pair
    inc ebx
    jmp .convert_loop

.success:
    mov eax, 1              ; Return 1 (success)
    jmp .done
.fail:
    xor eax, eax            ; Return 0 (failure)

.done:
    ; Clear registers
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi

    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
