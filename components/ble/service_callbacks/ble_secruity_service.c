
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_event.h"

#include "ble.h"
#include "ble_security_srv_pkt_handler.h"
#include "ble_security_service_enc_dec.h"
#include "ble_security_service.h"

#define TAG "BLE Security Service"

typedef enum e_ble_session_event
{
    BLE_SECURE_SESSION_EVENT_READY_EVENT = SECURE_BLE_PKT_TYPE_READY,
    BLE_SECURE_SESSION_CLI_PUB_KEY_EVENT = SECURE_BLE_PKT_TYPE_CLI_PUB_KEY,
    BLE_SECURE_SESSION_SRV_PUB_KEY_REQ_EVENT = SECURE_BLE_PKT_TYPE_SRV_PUB_KEY_REQ,
    BLE_SECURE_SESSION_READY_SESSION_EVENT = SECURE_BLE_PKT_TYPE_SESS_READY,
    BLE_SECURE_SESSION_DATA_EVENT = SECURE_BLE_PKT_TYPE_DATA,
    BLE_SECURE_SESSION_DATA_ACK_EVENT = SECURE_BLE_PKT_TYPE_DATA_ACK,
    BLE_SECURE_SESSION_EVENT_MAX,
} e_ble_session_event_t;

typedef struct s_ble_service_security_context
{
    uint8_t client_public_key[65];  /**< Client's ECDH public key */
    uint8_t device_public_key[65];  /**< Device's ECDH public key */
    uint8_t device_private_key[32]; /**< Device's ECDH private key */
    uint8_t shared_secret[32];      /**< ECDH shared secret */
    uint8_t session_key[32];        /**< Derived session key */
    uint8_t session_nonce[12];      /**< GCM nonce */
    uint8_t salt[32];               /**< Salt for encryption */
    uint32_t message_counter;       /**< Total messages encrypted */
} s_ble_service_security_context_t;

typedef struct s_ble_service_security_state_handler
{
    s_ble_service_security_context_t context;
    e_ble_security_service_states_t current_state;
} s_ble_service_security_state_handler_t;

static void ble_service_security_session_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

static esp_event_loop_handle_t loop_handle;
ESP_EVENT_DECLARE_BASE(BLE_SECURE_SESSION);

void ble_services_security_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    switch (event)
    {
    case ESP_GATTS_CONNECT_EVT:
    {
        esp_event_loop_args_t loop_args = {
            .queue_size = 25,
            .task_name = "ser-state-mch",
            .task_priority = 2,
            .task_stack_size = 4096,
            .task_core_id = 1,
        };

        ESP_ERROR_CHECK(esp_event_loop_create(&loop_args, &loop_handle));
        s_ble_service_security_state_handler_t *state_handler = (s_ble_service_security_state_handler_t *)malloc(sizeof(s_ble_service_security_state_handler_t));
        assert(state_handler);
        memset(state_handler, 0, sizeof(s_ble_service_security_state_handler_t));
        state_handler->current_state = BLE_SECURITY_SERVICE_STATE_IDEAL;
        ESP_ERROR_CHECK(esp_event_handler_register(BLE_SECURE_SESSION, ESP_EVENT_ANY_BASE, ble_service_security_session_event_handler, state_handler));
        break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
    {
        ESP_ERROR_CHECK(esp_event_loop_delete(loop_handle));
        break;
    }
    case ESP_GATTS_READ_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_READ_EVT");
        uint8_t *data = NULL;
        break;
    }
    case ESP_GATTS_WRITE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT for handle: 0x%02x", param->write.handle);
        s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_gatts_if(gatts_if);
        if (service_instance && service_instance->characteristics_len > 0 && service_instance->characteristics)
        {
            if (param->write.handle == service_instance->characteristics[BLE_SERVICE_SECURE_SESSION_CHAR_WRITE].char_handle)
            {
                s_secure_ble_packet_structure_t *packet = ble_secure_session_read_packet_and_send_event(param->write.value, param->write.len);
                if (packet && ble_secure_session_is_checksum_valid(packet))
                {
                    esp_event_post_to(loop_handle, BLE_SECURE_SESSION, packet->packet_type, packet, SECURE_BLE_TOTAL_PKT_SIZE, 1000 / portTICK_PERIOD_MS);
                }
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

static void ble_service_security_session_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (BLE_SECURE_SESSION == event_base)
    {
        s_ble_service_security_state_handler_t *state_handler = (s_ble_service_security_state_handler_t *)event_handler_arg;
        s_secure_ble_packet_structure_t *packet = (s_secure_ble_packet_structure_t *)event_data;
        switch (event_id)
        {
        case BLE_SECURE_SESSION_EVENT_READY_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_EVENT_READY_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_IDEAL == state_handler->current_state)
            {
                // Prepare pub-prv keys
                ble_secure_session_generate_device_key_value_ecdh(state_handler->context.device_public_key, state_handler->context.device_private_key);
                // Prepare ready ack packet
                uint8_t *data_ready_packet = NULL;
                int ret = ble_secure_session_prepare_ready_ack_packet(&data_ready_packet);
                if (-1 == ret)
                {
                    ESP_LOGE(TAG, "Something went wrong");
                    break;
                }
                // Send indication to C2 using READY_ACK
                // Start timer for 10 sec for cli pub key event
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_READY_PACKET_ACK_SENT;
            }
            break;
        }
        case BLE_SECURE_SESSION_CLI_PUB_KEY_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_CLI_PUB_KEY_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_READY_PACKET_ACK_SENT == state_handler->current_state)
            {
                // check the valieity of the the cli pub key
                // Prepare shared secret
                ble_secure_session_generate_shared_key(state_handler->context.client_public_key, state_handler->context.device_private_key, state_handler->context.shared_secret);
                // Prepare cli pub key ack packet with status code
                // Send indication to C2 about client pub key
                //  Start timer for 10 sec for server pub keu req event
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_CLIENT_PUB_KEY_SENT;
            }
            break;
        }
        case BLE_SECURE_SESSION_SRV_PUB_KEY_REQ_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_SRV_PUB_KEY_REQ_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_CLIENT_PUB_KEY_SENT == state_handler->current_state)
            {
                // Prepare pub key res packet
                // Send response to C3 about server's pub key
                // start timer for 10 sec for session ready event
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_SERVER_PUB_KEY_RES;
            }
            break;
        }
        case BLE_SECURE_SESSION_READY_SESSION_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_READY_SESSION_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_SERVER_PUB_KEY_RES == state_handler->current_state)
            {
                // Create session key
                ble_secure_session_generate_session_key(state_handler->context.shared_secret, state_handler->context.session_key, state_handler->context.salt);
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_SESSION_STARTED;
            }
            break;
        }
        case BLE_SECURE_SESSION_DATA_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_DATA_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_SESSION_STARTED == state_handler->current_state)
            {
                // Send data to the client
                // Start timer for 10 sec for data ack event
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_DATA_SENT;
            }
            break;
        }
        case BLE_SECURE_SESSION_DATA_ACK_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_DATA_ACK_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_DATA_SENT == state_handler->current_state)
            {
                // Send data to the client
                // Start timer for 10 sec for data ack event
                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_SESSION_STARTED;
            }
            break;
        }
        case BLE_SECURITY_SERVICE_STATE_TIMEOUT:
        {
            ESP_LOGE(TAG, "Timeout event, dropping connection");
            //  Disconnect the connected device
            break;
        }
        default:
        {
            ESP_LOGE(TAG, "Unknown event id: 0x%02x", event_id);
        }
        }
    }
}
