
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
    BLE_SECURE_SESSION_STATE_TIMEOUT = SECURE_BLE_PKT_TYPE_TIMEOUT,
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
static int ble_service_security_send_notification_packet(uint8_t *packet_buffer);

static esp_event_loop_handle_t loop_handle;
ESP_EVENT_DECLARE_BASE(BLE_SECURE_SESSION);
ESP_EVENT_DEFINE_BASE(BLE_SECURE_SESSION);

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
        ESP_ERROR_CHECK(esp_event_handler_register_with(loop_handle, BLE_SECURE_SESSION, ESP_EVENT_ANY_ID, ble_service_security_session_event_handler, state_handler));
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
        break;
    }
    case ESP_GATTS_WRITE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT for handle: 0x%02x(conn-id: %d)", param->write.handle, param->write.conn_id);
        s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_gatts_if(gatts_if);
        if (service_instance && service_instance->characteristics_len > 0 && service_instance->characteristics)
        {
            if (param->write.handle == service_instance->characteristics[BLE_SERVICE_SECURE_SESSION_CHAR_WRITE].char_handle)
            {
                s_secure_ble_packet_structure_t *packet = ble_secure_session_read_packet(param->write.value, param->write.len);
                if (packet && ble_secure_session_is_checksum_valid(packet))
                {
                    // ESP_LOG_BUFFER_HEXDUMP("Server write event", param->write.value, param->write.len, ESP_LOG_ERROR);
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
                uint8_t *ready_ack_packet_buffer = NULL;
                int ret = ble_secure_session_prepare_ready_ack_packet(&ready_ack_packet_buffer);
                if (-1 == ret)
                {
                    ESP_LOGE(TAG, "Something went wrong");
                    break;
                }

                // Send indication to C2 using READY_ACK
                ESP_LOGI(TAG, "Sending ready ack packet\n");
                if (-1 == ble_service_security_send_notification_packet(ready_ack_packet_buffer))
                {
                    ESP_LOGE(TAG, "Error sending ready ack packet");
                    break;
                }

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
                uint16_t cli_pub_key_status = 0x0001;
                // check the valieity of the the cli pub key
                memset(state_handler->context.client_public_key, 0, 65);
                memcpy(state_handler->context.client_public_key, packet->payload_data, 65);
                if (-1 == ble_secure_session_is_pub_key_valid(state_handler->context.client_public_key))
                {
                    ESP_LOGE(TAG, "Invalid client public key");
                    cli_pub_key_status = 0xFFFF;
                }
                else
                {
                    // Prepare shared secret
                    if (-1 == ble_secure_session_generate_shared_key(state_handler->context.client_public_key, state_handler->context.device_private_key, state_handler->context.shared_secret))
                    {
                        cli_pub_key_status = 0xFFFF;
                    }
                }

                // Prepare cli pub key ack packet with status code
                uint8_t *cli_pub_key_status_packet_buffer = NULL;
                if (-1 == ble_secure_session_prepare_cli_pub_key_status_packet(&cli_pub_key_status_packet_buffer, cli_pub_key_status))
                {
                    ESP_LOGE(TAG, "Somthing went wrong");
                    break;
                }

                // Send indication to C2 about client pub key
                ESP_LOGI(TAG, "Sending client public key status packet\n");
                if (-1 == ble_service_security_send_notification_packet(cli_pub_key_status_packet_buffer))
                {
                    ESP_LOGE(TAG, "Error sending client public key status packet");
                    break;
                }

                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_CLIENT_PUB_KEY_SENT;
                //  Start timer for 10 sec for server pub keu req event
                free(cli_pub_key_status_packet_buffer);
            }

            break;
        }
        case BLE_SECURE_SESSION_SRV_PUB_KEY_REQ_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_SRV_PUB_KEY_REQ_EVENT(%d, %d)", BLE_SECURITY_SERVICE_STATE_CLIENT_PUB_KEY_SENT, state_handler->current_state);
            if (BLE_SECURITY_SERVICE_STATE_CLIENT_PUB_KEY_SENT == state_handler->current_state)
            {
                // Prepare pub key res packet
                uint8_t *srv_pub_key_res_packet_buffer = NULL;
                int ret = ble_secure_session_prepare_srv_pub_key_res_packet(&srv_pub_key_res_packet_buffer, state_handler->context.device_public_key);
                if (-1 == ret)
                {
                    ESP_LOGE(TAG, "Something went wrong");
                    break;
                }

                // Send response to C2 about server's pub key
                ESP_LOGI(TAG, "Sending indication to client with server's public key\n");
                if (-1 == ble_service_security_send_notification_packet(srv_pub_key_res_packet_buffer))
                {
                    ESP_LOGE(TAG, "Error sending ready ack packet");
                    break;
                }
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
                int ret = ble_secure_session_generate_session_key(state_handler->context.shared_secret, state_handler->context.session_key, state_handler->context.salt);
                if (-1 == ret)
                {
                    ESP_LOGE(TAG, "Something went wrong");
                    break;
                }

                state_handler->current_state = BLE_SECURITY_SERVICE_STATE_SESSION_STARTED;
            }

            break;
        }
        case BLE_SECURE_SESSION_DATA_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_DATA_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_SESSION_STARTED == state_handler->current_state)
            {
                // Process incoming data
            }

            break;
        }
        case BLE_SECURE_SESSION_DATA_ACK_EVENT:
        {
            ESP_LOGI(TAG, "BLE_SECURE_SESSION_DATA_ACK_EVENT");
            if (BLE_SECURITY_SERVICE_STATE_DATA_SENT == state_handler->current_state)
            {
                // Process data ack event
            }

            break;
        }
        case BLE_SECURE_SESSION_STATE_TIMEOUT:
        {
            ESP_LOGE(TAG, "Timeout event, dropping connection");
            //  Disconnect the connected device
            break;
        }
        default:
        {
            ESP_LOGE(TAG, "Unknown event id: %ld", event_id);
        }
        }
    }
}

static int ble_service_security_send_notification_packet(uint8_t *packet_buffer)
{
    if (!packet_buffer)
    {
        ESP_LOGE(TAG, "Packet buffer null");
        return -1;
    }

    s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_id(BLE_PROFILE_ID_SECURE_SESSION);
    if (!service_instance || 0 == service_instance->characteristics_len)
    {
        ESP_LOGE(TAG, "Invalid service instance");
        return -1;
    }

    ESP_ERROR_CHECK(
        esp_ble_gatts_send_indicate(
            service_instance->gatts_if,
            service_instance->conn_id,
            service_instance->characteristics[BLE_SERVICE_SECURE_SESSION_CHAR_STATUS].char_handle,
            SECURE_BLE_TOTAL_PKT_SIZE,
            packet_buffer,
            false));

    return 0;
}


