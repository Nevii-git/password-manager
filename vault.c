#define _CRT_SECURE_NO_WARNINGS

#include "vault.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define VAULT_FILE "vault.bin"
#define MAGIC      "PWDVAULT"
#define MAGIC_LEN  8
#define VERSION    0x01

#define PWD_LINE_HEADER "PWDV1\n"

static unsigned char* g_vault_plain = NULL;
static size_t g_vault_len = 0;
static char g_master_password[256];

// -------- utilitaires --------

static int file_exists_internal(const char* path) {
    struct _stat st;
    return (_stat(path, &st) == 0);
}

static void secure_free(void* ptr, size_t len) {
    if (ptr) {
        sodium_memzero(ptr, len);
        free(ptr);
    }
}

// -------- dérivation de clé --------

static int derive_key_from_password(const char* password,
    const unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
    if (crypto_pwhash(key,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        password,
        strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1;
    }
    return 0;
}

// -------- chiffrement / sauvegarde --------

static int vault_encrypt_and_save(const char* filename,
    const char* password,
    const unsigned char* plaintext,
    size_t plaintext_len)
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    randombytes_buf(salt, sizeof salt);

    if (derive_key_from_password(password, salt, key) != 0) {
        return -1;
    }

    randombytes_buf(nonce, sizeof nonce);

    size_t ciphertext_len = plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        sodium_memzero(key, sizeof key);
        return -1;
    }

    unsigned long long clen;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &clen,
        plaintext, plaintext_len,
        NULL, 0,
        NULL, nonce, key) != 0) {
        free(ciphertext);
        sodium_memzero(key, sizeof key);
        return -1;
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        free(ciphertext);
        sodium_memzero(key, sizeof key);
        return -1;
    }

    fwrite(MAGIC, 1, MAGIC_LEN, f);
    fputc(VERSION, f);
    fwrite(salt, 1, sizeof salt, f);
    fwrite(nonce, 1, sizeof nonce, f);
    fwrite(ciphertext, 1, (size_t)clen, f);
    fclose(f);

    free(ciphertext);
    sodium_memzero(key, sizeof key);
    return 0;
}

static int vault_load_and_decrypt(const char* filename,
    const char* password,
    unsigned char** plaintext_out,
    size_t* plaintext_len_out)
{
    FILE* f = fopen(filename, "rb");
    if (!f) return -1;

    char magic_buf[MAGIC_LEN];
    if (fread(magic_buf, 1, MAGIC_LEN, f) != MAGIC_LEN ||
        memcmp(magic_buf, MAGIC, MAGIC_LEN) != 0) {
        fclose(f);
        return -1;
    }

    int version = fgetc(f);
    if (version != VERSION) {
        fclose(f);
        return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    if (fread(salt, 1, sizeof salt, f) != sizeof salt ||
        fread(nonce, 1, sizeof nonce, f) != sizeof nonce) {
        fclose(f);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long file_end = ftell(f);
    long cipher_offset = MAGIC_LEN + 1 + sizeof salt + sizeof nonce;
    long cipher_size = file_end - cipher_offset;
    if (cipher_size <= 0) {
        fclose(f);
        return -1;
    }
    fseek(f, cipher_offset, SEEK_SET);

    unsigned char* ciphertext = malloc((size_t)cipher_size);
    if (!ciphertext) {
        fclose(f);
        return -1;
    }

    if (fread(ciphertext, 1, (size_t)cipher_size, f) != (size_t)cipher_size) {
        fclose(f);
        free(ciphertext);
        return -1;
    }
    fclose(f);

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_key_from_password(password, salt, key) != 0) {
        free(ciphertext);
        return -1;
    }

    size_t max_plain_len = (size_t)cipher_size - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char* plaintext = malloc(max_plain_len);
    if (!plaintext) {
        free(ciphertext);
        sodium_memzero(key, sizeof key);
        return -1;
    }

    unsigned long long plen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &plen,
        NULL,
        ciphertext, (unsigned long long)cipher_size,
        NULL, 0,
        nonce, key) != 0) {
        free(ciphertext);
        secure_free(plaintext, max_plain_len);
        sodium_memzero(key, sizeof key);
        return -1;
    }

    free(ciphertext);
    sodium_memzero(key, sizeof key);

    *plaintext_out = plaintext;
    *plaintext_len_out = (size_t)plen;
    return 0;
}

// -------- gestion du coffre en mémoire --------

static int init_empty_vault(void) {
    const char* header = PWD_LINE_HEADER;
    g_vault_len = strlen(header);
    g_vault_plain = malloc(g_vault_len + 1);
    if (!g_vault_plain) return -1;
    memcpy(g_vault_plain, header, g_vault_len + 1);
    return 0;
}

static int save_current_vault(void) {
    if (!g_vault_plain) {
        if (init_empty_vault() != 0) return -1;
    }
    if (vault_encrypt_and_save(VAULT_FILE, g_master_password,
        g_vault_plain, g_vault_len) != 0) {
        return -1;
    }
    return 0;
}

// -------- API publique --------

int vault_sodium_init(void) {
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

bool vault_exists(void) {
    return file_exists_internal(VAULT_FILE) != 0;
}

int vault_create_new(const char* master_pwd) {
    memset(g_master_password, 0, sizeof g_master_password);
    strncpy_s(g_master_password, sizeof g_master_password, master_pwd, _TRUNCATE);

    if (init_empty_vault() != 0) return -1;
    if (save_current_vault() != 0) return -1;
    return 0;
}

int vault_open(const char* master_pwd) {
    memset(g_master_password, 0, sizeof g_master_password);
    strncpy_s(g_master_password, sizeof g_master_password, master_pwd, _TRUNCATE);

    if (vault_load_and_decrypt(VAULT_FILE, g_master_password,
        &g_vault_plain, &g_vault_len) != 0) {
        return -1;
    }

    if (g_vault_len < strlen(PWD_LINE_HEADER) ||
        strncmp((char*)g_vault_plain, PWD_LINE_HEADER, strlen(PWD_LINE_HEADER)) != 0) {
        return -1;
    }

    return 0;
}

int vault_add_entry(const char* site, const char* id, const char* password) {
    if (!g_vault_plain) {
        if (init_empty_vault() != 0) return -1;
    }

    size_t line_len = strlen(site) + 1 + strlen(id) + 1 + strlen(password) + 1;
    char* line = malloc(line_len + 1);
    if (!line) return -1;

    snprintf(line, line_len + 1, "%s\t%s\t%s\n", site, id, password);

    size_t new_len = g_vault_len + strlen(line);
    unsigned char* new_buf = realloc(g_vault_plain, new_len + 1);
    if (!new_buf) {
        free(line);
        return -1;
    }

    memcpy(new_buf + g_vault_len, line, strlen(line) + 1);
    g_vault_plain = new_buf;
    g_vault_len = new_len;

    free(line);

    if (save_current_vault() != 0) return -1;
    return 0;
}

char* vault_get_all_entries(void) {
    if (!g_vault_plain) {
        if (init_empty_vault() != 0) return NULL;
    }

    char* ptr = strstr((char*)g_vault_plain, "\n");
    if (!ptr) {
        return _strdup("");
    }
    ptr++; // après PWDV1\n

    return _strdup(ptr);
}

void vault_generate_password(char* out, size_t len) {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*_-+";

    size_t charset_len = strlen(charset);
    if (len == 0) return;

    for (size_t i = 0; i < len; ++i) {
        out[i] = charset[randombytes_uniform((uint32_t)charset_len)];
    }
    out[len] = '\0';
}

void vault_cleanup(void) {
    if (g_vault_plain) {
        secure_free(g_vault_plain, g_vault_len);
        g_vault_plain = NULL;
        g_vault_len = 0;
    }
    sodium_memzero(g_master_password, sizeof g_master_password);
}
