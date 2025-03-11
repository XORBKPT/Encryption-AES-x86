#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <mbedtls/aes.h>

#define MAX_MESSAGE_LEN 256

// Read a line from stdin, trimming newline and trailing whitespace
int read_line(char *buffer, int max_len) {
    if (!fgets(buffer, max_len, stdin)) return 0;
    int len = strlen(buffer);
    while (len > 0 && isspace(buffer[len - 1])) buffer[--len] = 0;
    return len;
}

// Convert hex string to bytes, return 1 on success, 0 on failure
int hex_to_bytes(const char *hex, unsigned char *bytes, int byte_len) {
    for (int i = 0; i < byte_len * 2; i++) {
        if (!isxdigit(hex[i])) return 0;
    }
    for (int i = 0; i < byte_len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
    return 1;
}

// Convert bytes to hex string
void bytes_to_hex(const unsigned char *bytes, int len, char *hex) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02X", bytes[i]);
    }
    hex[len * 2] = 0;
}

// Apply PKCS7 padding
int pkcs7_pad(const char *input, int input_len, unsigned char *output, int max_len) {
    int pad_len = 16 - (input_len % 16);
    if (input_len + pad_len > max_len) return 0;
    memcpy(output, input, input_len);
    for (int i = 0; i < pad_len; i++) {
        output[input_len + i] = (unsigned char)pad_len;
    }
    return input_len + pad_len;
}

// Print bytes as formatted hex
void print_formatted_hex(const char *hex) {
    int len = strlen(hex);
    for (int i = 0; i < len; i++) {
        putchar(hex[i]);
        if ((i + 1) % 32 == 0) printf("\n");
        else if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}

// Self-test with NIST vectors
int self_test() {
    const char *key_hex = "000102030405060708090A0B0C0D0E0F";
    const char *iv_hex = "101112131415161718191A1B1C1D1E1F";
    const char *plain_hex = "00112233445566778899AABBCCDDEEFF";
    const char *expected_hex = "69C4E0D86A7B0430D8CDB78070B4C55A";
    unsigned char key[16], iv[16], plain[16], cipher[16], output[33];
    mbedtls_aes_context aes;

    hex_to_bytes(key_hex, key, 16);
    hex_to_bytes(iv_hex, iv, 16);
    hex_to_bytes(plain_hex, plain, 16);

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, plain, cipher);
    mbedtls_aes_free(&aes);

    bytes_to_hex(cipher, 16, output);
    return strcmp(output, expected_hex) == 0;
}

int main() {
    char message[MAX_MESSAGE_LEN], key_hex[33], iv_hex[33];
    unsigned char key[16], iv[16], padded[MAX_MESSAGE_LEN + 16], cipher[MAX_MESSAGE_LEN + 16];
    char hex_output[(MAX_MESSAGE_LEN + 16) * 2 + 1];
    mbedtls_aes_context aes;

    if (!self_test()) {
        printf("Self-test failed!\n");
        return 1;
    }

    printf("Pico Message Gadget\n");
    printf("Enter characters including spaces: ");
    int msg_len = read_line(message, MAX_MESSAGE_LEN);
    if (msg_len == 0) {
        printf("Error: Message too long.\n");
        return 1;
    }

    printf("Enter 32 capital hex letters (secret key): ");
    if (read_line(key_hex, 33) != 32 || !hex_to_bytes(key_hex, key, 16)) {
        printf("Error: Invalid key.\n");
        return 1;
    }

    printf("Enter 32 capital hex letters (IV, PKCS7 padding): ");
    if (read_line(iv_hex, 33) != 32 || !hex_to_bytes(iv_hex, iv, 16)) {
        printf("Error: Invalid IV.\n");
        return 1;
    }

    int padded_len = pkcs7_pad(message, msg_len, padded, MAX_MESSAGE_LEN + 16);
    if (!padded_len) {
        printf("Error: Padding failed.\n");
        return 1;
    }

    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
        printf("Error: Failed to set key.\n");
        mbedtls_aes_free(&aes);
        return 1;
    }

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded, cipher);
    mbedtls_aes_free(&aes);

    bytes_to_hex(cipher, padded_len, hex_output);
    print_formatted_hex(hex_output);

    printf("Keys will be erased from RAM when the program exits.\n");

    // Explicitly clear sensitive memory
    memset(key, 0, 16);
    memset(iv, 0, 16);
    memset(padded, 0, MAX_MESSAGE_LEN + 16);
    memset(cipher, 0, MAX_MESSAGE_LEN + 16);

    return 0;
}
