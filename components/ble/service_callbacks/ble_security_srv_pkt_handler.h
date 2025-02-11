

#ifndef __BLE_SECURITY_SRV_PKT_HANDLER_H__
#define __BLE_SECURITY_SRV_PKT_HANDLER_H__

#include "stdint.h"

#define SECURE_BLE_TOTAL_PKT_SIZE 450
#define SECURE_BLE_IV_SIZE 12
#define SECURE_BLE_TAG_SIZE 6
#define SECURE_BLE_PAYLOAD_DATA_SIZE 421
#define SECURE_BLE_CHECKSUM_SIZE 4

#define SECURE_BLE_PKT_TYPE_READY 0x01
#define SECURE_BLE_PKT_TYPE_READY_ACK 0x02
#define SECURE_BLE_PKT_TYPE_CLI_PUB_KEY 0x03
#define SECURE_BLE_PKT_TYPE_CLI_PUB_KEY_STATUS 0x04
#define SECURE_BLE_PKT_TYPE_SRV_PUB_KEY_REQ 0x05
#define SECURE_BLE_PKT_TYPE_SRV_PUB_KEY_RES 0x06
#define SECURE_BLE_PKT_TYPE_SESS_READY 0x07
#define SECURE_BLE_PKT_TYPE_DATA 0x08
#define SECURE_BLE_PKT_TYPE_DATA_ACK 0x09
#define SECURE_BLE_PKT_TYPE_TIMEOUT 0x0A
#define SECURE_BLE_PKT_TYPE_INVALID 0xFF

#define SECURE_BLE_PAYLOAD_TYPE_UNDEFINED 0xFF // While transmitting unencrypted payload i.e. during key exchange
#define SECURE_BLE_PAYLOAD_TYPE_WIFI 0x11      // Containg both wifi ssid and password both 32-bytes
#define SECURE_BLE_PAYLOAD_TYPE_AWS_ROOT_CA_CRT 0x12
#define SECURE_BLE_PAYLOAD_TYPE_AWS_DEVICE_CRT 0x13
#define SECURE_BLE_PAYLOAD_TYPE_AWS_PRIVATE_KEY 0x14
#define SECURE_BLE_PAYLOAD_TYPE_THINGS_BOARD_ROOT_CA_CRT 0x15

typedef uint8_t ble_secure_packet_type_t;
typedef uint8_t ble_secure_payload_type_t;

typedef struct s_secure_ble_packet_structure
{
    ble_secure_packet_type_t packet_type;
    uint8_t packet_id;
    uint16_t payload_size;
    ble_secure_payload_type_t payload_type;
    uint8_t total_chunk;
    uint8_t chunk_index;
    uint8_t iv[SECURE_BLE_IV_SIZE];
    uint8_t tag[SECURE_BLE_TAG_SIZE];
    uint8_t payload_data[SECURE_BLE_PAYLOAD_DATA_SIZE];
    uint8_t checksum[SECURE_BLE_CHECKSUM_SIZE];
} s_secure_ble_packet_structure_t;

s_secure_ble_packet_structure_t *ble_secure_session_read_packet(uint8_t *data, size_t len);
bool ble_secure_session_is_checksum_valid(s_secure_ble_packet_structure_t *packet);

int ble_secure_session_prepare_ready_ack_packet(uint8_t **ready_packet_buffer);
int ble_secure_session_prepare_cli_pub_key_status_packet(uint8_t **cli_pub_key_status_packet_buffer, uint16_t cli_pub_key_status);
int ble_secure_session_prepare_srv_pub_key_res_packet(uint8_t **srv_pub_key_packet_buffer, uint8_t srv_pub_key[65]);
int ble_secure_session_prepare_wifi_data_payload_packet(uint8_t **wifi_payload_packet_buffer, uint8_t ssid[32], uint8_t psk[32]);


#endif // __BLE_SECURITY_SRV_PKT_HANDLER_H__
