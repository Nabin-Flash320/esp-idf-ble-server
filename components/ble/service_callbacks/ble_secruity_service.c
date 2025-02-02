
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ctr_drbg.h"

#include "ble.h"

#define TAG "BLE Security Service"

typedef struct s_ble_service_security_context
{
    uint8_t client_public_key[65];  /**< Client's ECDH public key */
    uint8_t device_public_key[65];  /**< Device's ECDH public key */
    uint8_t device_private_key[32]; /**< Device's ECDH private key */
    uint8_t shared_secret[32];      /**< ECDH shared secret */
    uint8_t session_key[32];        /**< Derived session key */
    uint8_t session_nonce[12];      /**< GCM nonce */
    uint8_t salt[32];               /**< Salt for encryption */
    bool session_active;            /**< Wehater the session has started */
    uint32_t message_counter;       /**< Total messages encrypted */
} s_ble_service_security_context_t;

static int ble_secure_session_start_context(uint8_t *public_key, uint16_t len);
static int ble_secure_session_generate_device_key_value_ecdh();
static int ble_secure_session_generate_shared_key();
static int ble_secure_session_generate_session_key();

static s_ble_service_security_context_t ble_secure_session_context;
static mbedtls_ecp_group group;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_mpi d;
static mbedtls_ecp_point Q;
static mbedtls_entropy_context entropy;
static mbedtls_mpi z;

void ble_services_security_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    switch (event)
    {
    case ESP_GATTS_READ_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_READ_EVT");

        s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_gatts_if(gatts_if);
        if (service_instance)
        {
            int i = 0;
            for (; i < service_instance->characteristics_len; i++)
            {
                if (param->write.handle == service_instance->characteristics[i].char_handle)
                {
                    break;
                }
            }

            if ((i == BLE_SERVICE_SECURITY_CHAR_ID_SECURE_SESSION_START) && (ble_secure_session_context.session_active))
            {
                esp_gatt_rsp_t response = {
                    .attr_value = {
                        .len = 65,
                        .handle = param->write.handle,
                    },
                };

                memset(response.attr_value.value, 0, sizeof(response.attr_value.value));
                memcpy(response.attr_value.value, ble_secure_session_context.device_public_key, response.attr_value.len);
                ESP_LOG_BUFFER_HEXDUMP("Response: ", response.attr_value.value, sizeof(response.attr_value.value), ESP_LOG_ERROR);
                ESP_ERROR_CHECK(esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &response));
            }
            else
            {
                esp_gatt_rsp_t response = {
                    .attr_value = {
                        .value[0] = ble_secure_session_context.session_active,
                        .len = sizeof(ble_secure_session_context.session_active),
                        .handle = param->read.handle,
                    },
                };
                ESP_ERROR_CHECK(esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &response));
            }
        }

        break;
    }
    case ESP_GATTS_WRITE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT for handle: 0x%02x", param->write.handle);

        s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_gatts_if(gatts_if);
        if (service_instance)
        {
            int i = 0;
            for (; i < service_instance->characteristics_len; i++)
            {
                if (param->write.handle == service_instance->characteristics[i].char_handle)
                {
                    break;
                }
            }

            if (i == BLE_SERVICE_SECURITY_CHAR_ID_SECURE_SESSION_START)
            {
                // The public key provided to the device should be of 32 bytes
                // 64-byte public key (Uncompressed format)
                uint8_t client_public_key[65] = {
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

                if (!ble_secure_session_context.session_active)
                {
                    ble_secure_session_start_context(client_public_key, sizeof(client_public_key));
                }

                esp_gatt_rsp_t response = {
                    .attr_value = {
                        .value[0] = 0x01,
                        .len = 1,
                        .handle = param->write.handle,
                    },
                };
                ESP_ERROR_CHECK(esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &response));
            }
        }

        break;
    }
    case ESP_GATTS_EXEC_WRITE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_EXEC_WRITE_EVT");
        break;
    }
    case ESP_GATTS_DELETE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_DELETE_EVT(status: 0x%x; service_handle: 0x%02x)", param->del.status, param->del.service_handle);
        break;
    }
    case ESP_GATTS_STOP_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_STOP_EVT(status: 0x%x; service_handle: 0x%02x)", param->stop.status, param->stop.service_handle);
        break;
    }
    default:
    {
        break;
    }
    }
}

static int ble_secure_session_start_context(uint8_t *public_key, uint16_t len)
{
    if (ble_secure_session_context.session_active)
    {
        ESP_LOGE(TAG, "Errror starting session BLE secure session already started");
        return -1;
    }

    if (len > 65)
    {
        ESP_LOGE(TAG, "Error starting session public key length invalid");
        return -1;
    }

    memset(&ble_secure_session_context, 0, sizeof(s_ble_service_security_context_t));
    memcpy(ble_secure_session_context.client_public_key, public_key, len);
    // Genereate device private and public key
    ble_secure_session_generate_device_key_value_ecdh();
    ble_secure_session_generate_shared_key();
#warning("Use nonce to encrypt data along with session key and then transmit nonce to the client")
    ble_secure_session_generate_session_key();
    ble_secure_session_context.session_active = true;
    ESP_LOG_BUFFER_HEXDUMP("Client pub key", ble_secure_session_context.client_public_key, sizeof(ble_secure_session_context.client_public_key), ESP_LOG_ERROR);
    printf("\n");
    ESP_LOG_BUFFER_HEXDUMP("Device prv key", ble_secure_session_context.device_private_key, sizeof(ble_secure_session_context.device_private_key), ESP_LOG_ERROR);
    printf("\n");
    ESP_LOG_BUFFER_HEXDUMP("Device pub key", ble_secure_session_context.device_public_key, sizeof(ble_secure_session_context.device_public_key), ESP_LOG_ERROR);
    printf("\n");
    ESP_LOG_BUFFER_HEXDUMP("Shared key", ble_secure_session_context.shared_secret, sizeof(ble_secure_session_context.shared_secret), ESP_LOG_ERROR);
    printf("\n");
    ESP_LOG_BUFFER_HEXDUMP("Session key", ble_secure_session_context.session_key, sizeof(ble_secure_session_context.session_key), ESP_LOG_ERROR);
    return 0;
}

static int ble_secure_session_generate_device_key_value_ecdh()
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

    ret = mbedtls_mpi_write_binary(&d, ble_secure_session_context.device_private_key, 32);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error writing private key(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecp_point_write_binary(&group, &Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                         ble_secure_session_context.device_public_key, sizeof(ble_secure_session_context.device_public_key));
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

static int ble_secure_session_generate_shared_key()
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
        goto ret_exit;
    }

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error group load(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecp_point_read_binary(&group, &Q, ble_secure_session_context.client_public_key, sizeof(ble_secure_session_context.client_public_key));
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error loading client public key(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecp_check_pubkey(&group, &Q);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Client public key validation failed (error: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_mpi_read_binary(&d, ble_secure_session_context.device_private_key, sizeof(ble_secure_session_context.device_private_key));
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error loading device private key(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_ecdh_compute_shared(&group, &z, &Q, &d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error computing shared key(eror: %d)", ret);
        goto ret_exit;
    }

    ret = mbedtls_mpi_write_binary(&z, ble_secure_session_context.shared_secret, sizeof(ble_secure_session_context.shared_secret));
    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error copying shared key(eror: %d)", ret);
        goto ret_exit;
    }

ret_exit:
    mbedtls_ecp_group_free(&group);
    mbedtls_mpi_free(&z);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);

    return 0;
}

static int ble_secure_session_generate_session_key()
{
#warning("Use salt to create randomness in future")
    const char *info = "BLE Secure Session Key";

    int ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        ble_secure_session_context.salt,
        sizeof(ble_secure_session_context.salt),
        ble_secure_session_context.shared_secret,
        sizeof(ble_secure_session_context.shared_secret),
        (uint8_t *)info,
        strlen(info),
        ble_secure_session_context.session_key,
        sizeof(ble_secure_session_context.session_key));

    if (0 != ret)
    {
        ESP_LOGE(TAG, "Error generating session key");
        return -1;
    }

    return 0;
}
