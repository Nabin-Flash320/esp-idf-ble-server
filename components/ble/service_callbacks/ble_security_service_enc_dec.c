
#include "string.h"
#include "stdio.h"

#include "esp_log.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ctr_drbg.h"

#include "ble.h"
#include "ble_security_service_enc_dec.h"

#define TAG "BLE enc dec"

static mbedtls_ecp_group group;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_mpi d;
static mbedtls_ecp_point Q;
static mbedtls_entropy_context entropy;
static mbedtls_mpi z;
static uint8_t data_buffer[256];
const uint8_t client_public_key[65] = {
    0x04, // Uncompressed format prefix
    // X coordinate (32 bytes)
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    // Y coordinate (32 bytes)
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};

int ble_secure_session_generate_device_key_value_ecdh(uint8_t device_public_key[65], uint8_t device_private_key[32])
{
    size_t olen;

    mbedtls_ecp_group_init(&group);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error creating seed(error: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error group load(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecdh_gen_public(&group, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error generating key pair(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_mpi_write_binary(&d, device_private_key, 32);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error writing private key(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecp_point_write_binary(&group, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, device_public_key, 65);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error writing public key(eror: %d)", ret);
        goto ret_exit;
    }

ret_exit:
    mbedtls_ecp_group_free(&group);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);

    return 0;
}

int ble_secure_session_generate_shared_key(uint8_t client_public_key[65], uint8_t device_private_key[32], uint8_t shared_secret[32])
{
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&z);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error creating seed(error: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error group load(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecp_point_read_binary(&group, &Q, client_public_key, 65);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error loading client public key(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecp_check_pubkey(&group, &Q);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Client public key validation failed (error: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_mpi_read_binary(&d, device_private_key, 32);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error loading device private key(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecdh_compute_shared(&group, &z, &Q, &d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error computing shared key(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_mpi_write_binary(&z, shared_secret, 32);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error copying shared key(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

ret_exit:
    mbedtls_ecp_group_free(&group);
    mbedtls_mpi_free(&z);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);

    return ret;
}

int ble_secure_session_generate_session_key(uint8_t shared_secret[32], uint8_t session_key[32], uint8_t salt[32])
{
#warning("Use salt to create randomness in future")
    const char *info = "BLE Secure Session Key";

    int ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt,
        32,
        shared_secret,
        32,
        (uint8_t *)info,
        strlen(info),
        session_key,
        32);

    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error generating session key");
        return -1;
    }

    return 0;
}

int ble_secure_session_is_pub_key_valid(uint8_t pub_key_to_check[65])
{
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error group load(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecp_point_read_binary(&group, &Q, client_public_key, 65);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error loading client public key(eror: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

    ret = mbedtls_ecp_check_pubkey(&group, &Q);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Client public key validation failed (error: %d)", ret);
        ret = -1;
        goto ret_exit;
    }

ret_exit:
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_point_free(&Q);
    return 0 == ret ? 0 : -1;
}
