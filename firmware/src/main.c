#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_random.h"
#include "esp_hmac.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "aes/esp_aes.h"

#define UART_PORT_NUM    UART_NUM_0
#define MAX_FILE         3072
#define RX_SIZE          (2 * MAX_FILE + 64)
#define AES_BLOCK_SIZE   16
#define KEY_LEN          32
#define MAX_BLOB         (AES_BLOCK_SIZE + MAX_FILE + AES_BLOCK_SIZE)

#define KEY_LABEL        "stage-st2i-esp32"   // HMAC label since the software can't read BLOCK_KEY0
#define NVS_NS           "vault"
#define NVS_BLOB         "blob"               // stored ciphertext
#define NVS_VERIFY       "pwverify"           // stored passphrase verifier

//SETUP
static uint8_t vault_key[KEY_LEN];
static bool    key_ready = false;
static bool    session_unlocked = false;
static uint8_t s_rx[RX_SIZE];
static uint8_t s_bin[MAX_FILE];
static uint8_t s_blob[MAX_BLOB];
static uint8_t s_plain[MAX_BLOB];
static uint8_t s_padded[MAX_FILE + AES_BLOCK_SIZE];
static char    s_hex[2 * MAX_BLOB + 1];

//Raw Bytes -> Hex Characters
static void to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *H = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) { out[2*i]=H[in[i]>>4]; out[2*i+1]=H[in[i]&0x0F]; }
    out[2*len] = '\0';
}

//Hex Characters -> Raw Bytes
static int from_hex(const char *in, uint8_t *out, size_t cap) {
    size_t n = strlen(in);
    if (n % 2) return -1;
    size_t b = n/2; if (b > cap) return -1;
    for (size_t i=0;i<b;i++){
        char hi=in[2*i], lo=in[2*i+1];
        int h=(hi>='0'&&hi<='9')?hi-'0':(hi>='a'&&hi<='f')?hi-'a'+10:(hi>='A'&&hi<='F')?hi-'A'+10:-1;
        int l=(lo>='0'&&lo<='9')?lo-'0':(lo>='a'&&lo<='f')?lo-'a'+10:(lo>='A'&&lo<='F')?lo-'A'+10:-1;
        if(h<0||l<0) return -1;
        out[i]=(uint8_t)((h<<4)|l);
    }
    return (int)b;
}

// AES key: eFuse  + label. Passphrase != Key.
static bool derive_vault_key(void) {
    return esp_hmac_calculate(HMAC_KEY0, (const uint8_t*)KEY_LABEL,
                              strlen(KEY_LABEL), vault_key) == ESP_OK;
}

// Passphrase verifier. HMAC(eFuse, passphrase).
static bool passphrase_verifier(const char *pass, uint8_t out[32]) {
    return esp_hmac_calculate(HMAC_KEY0, (const uint8_t*)pass,
                              strlen(pass), out) == ESP_OK;
}

static bool nvs_get(const char *k, uint8_t *out, size_t cap, size_t *len) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    size_t sz = cap; esp_err_t e = nvs_get_blob(h, k, out, &sz);
    nvs_close(h);
    if (e != ESP_OK) return false;
    if (len) *len = sz;
    return true;
}
static bool nvs_put(const char *k, const uint8_t *v, size_t len) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t e = nvs_set_blob(h, k, v, len);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK;
}

static int vault_encrypt(const uint8_t *pt, size_t pt_len, uint8_t *blob) {
    size_t pad = AES_BLOCK_SIZE - (pt_len % AES_BLOCK_SIZE);
    size_t ct_len = pt_len + pad;
    if (16 + ct_len > MAX_BLOB) return -1;
    memcpy(s_padded, pt, pt_len);
    memset(s_padded + pt_len, (uint8_t)pad, pad);
    uint8_t iv[16]; esp_fill_random(iv, sizeof(iv));
    memcpy(blob, iv, 16);
    esp_aes_context aes; esp_aes_init(&aes);
    esp_aes_setkey(&aes, vault_key, 256);
    esp_aes_crypt_cbc(&aes, ESP_AES_ENCRYPT, ct_len, iv, s_padded, blob+16);
    esp_aes_free(&aes);
    return (int)(16 + ct_len);
}
static int vault_decrypt(const uint8_t *blob, size_t blob_len, uint8_t *pt) {
    if (blob_len < 32 || (blob_len-16)%AES_BLOCK_SIZE) return -1;
    size_t ct_len = blob_len - 16;
    uint8_t iv[16]; memcpy(iv, blob, 16);
    esp_aes_context aes; esp_aes_init(&aes);
    esp_aes_setkey(&aes, vault_key, 256);
    esp_aes_crypt_cbc(&aes, ESP_AES_DECRYPT, ct_len, iv, blob+16, pt);
    esp_aes_free(&aes);
    uint8_t pad = pt[ct_len-1];
    if (pad<1||pad>AES_BLOCK_SIZE||pad>ct_len) return -1;
    return (int)(ct_len - pad);
}

void app_main(void) {
    esp_err_t nv = nvs_flash_init();
    if (nv==ESP_ERR_NVS_NO_FREE_PAGES||nv==ESP_ERR_NVS_NEW_VERSION_FOUND){ nvs_flash_erase(); nvs_flash_init(); }
    key_ready = derive_vault_key();

    uart_config_t uc = { .baud_rate=115200, .data_bits=UART_DATA_8_BITS,
        .parity=UART_PARITY_DISABLE, .stop_bits=UART_STOP_BITS_1,
        .flow_ctrl=UART_HW_FLOWCTRL_DISABLE, .source_clk=UART_SCLK_DEFAULT };
    uart_driver_install(UART_PORT_NUM, RX_SIZE + 256, 0, 0, NULL, 0);
    uart_param_config(UART_PORT_NUM, &uc);

    printf("[*] ESP32 Secure Vault Online. Key from eFuse (%s). Locked.\n",
           key_ready ? "OK" : "FAILED");

    while (1) {
        int len = uart_read_bytes(UART_PORT_NUM, s_rx, RX_SIZE-1, 50/portTICK_PERIOD_MS);
        if (len <= 0) { vTaskDelay(10/portTICK_PERIOD_MS); continue; }
        s_rx[len] = '\0';
        char *msg = (char*)s_rx;
        if (!key_ready) { printf("ERROR: Key not available\n"); continue; }

        // Passphrase : Set-Once or Skip
        if (strncmp(msg, "SETPASS:", 8) == 0) {
            uint8_t tmp[32];
            if (nvs_get(NVS_VERIFY, tmp, sizeof(tmp), NULL)) {
                printf("ERROR: Passphrase already set\n");
                memset(tmp, 0, 32);
            } else {
                char *pass = strtok(msg+8, "\r\n");
                if (!pass || !strlen(pass)) { printf("ERROR: Empty\n"); continue; }
                uint8_t v[32];
                if (!passphrase_verifier(pass, v)) { printf("ERROR: Derive\n"); continue; }
                if (nvs_put(NVS_VERIFY, v, 32)) printf("OK: Passphrase set\n");
                else printf("ERROR: Store Failed\n");
                memset(v, 0, 32);
            }
        }
        // Authentication
        else if (strncmp(msg, "AUTH:", 5) == 0) {
            char *pass = strtok(msg+5, "\r\n");
            uint8_t stored[32], attempt[32];
            if (!pass || !nvs_get(NVS_VERIFY, stored, sizeof(stored), NULL)) {
                printf("ERROR: Not Provisioned\n");
            } else if (passphrase_verifier(pass, attempt) && memcmp(stored, attempt, 32)==0) {
                session_unlocked = true;
                printf("UNLOCKED: Authenticated\n");
            } else {
                printf("ERROR: Auth Failed\n");
            }
            memset(stored,0,32); memset(attempt,0,32);
        }
        // Locking
        else if (strncmp(msg, "LOCK", 4) == 0) {
            session_unlocked = false;
            printf("LOCKED: Session ended\n");
        }
        // ========================================= After AUthnetification =========================================
        else if (!session_unlocked) {
            printf("ERROR: Locked - authenticate first\n");
        }
        // Encrypt
        else if (strncmp(msg, "ENCFILE:", 8) == 0) {
            char *hex = strtok(msg+8, "\r\n");
            if (!hex) { printf("ERROR: Empty\n"); continue; }
            int nb = from_hex(hex, s_bin, sizeof(s_bin));
            if (nb < 0) { printf("ERROR: Bad Hex or Too Large\n"); continue; }
            int bl = vault_encrypt(s_bin, nb, s_blob);
            if (bl < 0 || !nvs_put(NVS_BLOB, s_blob, bl)) printf("ERROR: Store Failed\n");
            else printf("OK: Encrypted and stored %d bytes\n", nb);
        }
        // Decrypt
        else if (strncmp(msg, "DEC", 3) == 0) {
            size_t bl;
            if (!nvs_get(NVS_BLOB, s_blob, sizeof(s_blob), &bl)) printf("ERROR: Vault Empty\n");
            else {
                int pl = vault_decrypt(s_blob, bl, s_plain);
                if (pl < 0) printf("ERROR: Decrypt Failed\n");
                else { to_hex(s_plain, pl, s_hex); printf("PLAIN:%s\n", s_hex); }
            }
        }
        // Display
        else if (strncmp(msg, "DISPLAY", 7) == 0) {
            size_t bl;
            if (!nvs_get(NVS_BLOB, s_blob, sizeof(s_blob), &bl)) printf("ERROR: Vault Empty\n");
            else { to_hex(s_blob, bl, s_hex); printf("STORED:%s\n", s_hex); }
        }
        // Delete
        else if (strncmp(msg, "DELETE", 6) == 0) {
            nvs_handle_t h;
            if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) printf("ERROR: Open Failed\n");
            else {
                esp_err_t e = nvs_erase_key(h, NVS_BLOB);
                if (e==ESP_OK) e = nvs_commit(h);
                nvs_close(h);
                if (e==ESP_OK) printf("DELETED: Vault wiped\n");
                else if (e==ESP_ERR_NVS_NOT_FOUND) printf("DELETED: Already empty\n");
                else printf("ERROR: Delete Failed\n");
            }
        }

        vTaskDelay(10/portTICK_PERIOD_MS);
    }
}