
#include <stdlib.h>
#include <string.h>

#include "esp_rom_crc.h"
#include "esp_log.h"

#include "ble.h"
#include "ble_security_srv_pkt_handler.h"

#define BLE_SECURE_SERVICE_PKT_TAG "SECURE_PKT"

s_secure_ble_packet_structure_t *ble_secure_session_read_packet(uint8_t *data, size_t len)
{
    if(len != SECURE_BLE_TOTAL_PKT_SIZE)
    {
        ESP_LOGI(BLE_SECURE_SERVICE_PKT_TAG, "Pakcet size expected %d got %d", SECURE_BLE_TOTAL_PKT_SIZE, len);
        return NULL;
    }


    s_secure_ble_packet_structure_t *packet = (s_secure_ble_packet_structure_t*)malloc(sizeof(s_secure_ble_packet_structure_t));
    if(!packet)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Unable to allocate memory for packet");
        return NULL;
    }

    memset(packet, 0, sizeof(s_secure_ble_packet_structure_t));
    memcpy(packet, data, SECURE_BLE_TOTAL_PKT_SIZE);
    return packet;
}

bool ble_secure_session_is_checksum_valid(s_secure_ble_packet_structure_t *packet)
{
    if(!packet)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Innvalid packet");
        return false;
    }

    uint8_t packet_checksum[SECURE_BLE_CHECKSUM_SIZE];
    memcpy(packet_checksum, packet->checksum, SECURE_BLE_CHECKSUM_SIZE);
    uint32_t crc_claculated = esp_rom_crc32_le(0, (uint8_t*)packet, SECURE_BLE_TOTAL_PKT_SIZE - SECURE_BLE_CHECKSUM_SIZE);
    if(0 != memcmp(packet_checksum, &crc_claculated, SECURE_BLE_CHECKSUM_SIZE))
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Invalid data, checksum didn't match");
        return false;
    }
    
    return true;
}

int ble_secure_session_prepare_ready_ack_packet(uint8_t **ready_packet_buffer)
{
    s_secure_ble_packet_structure_t ready_ack_packet = {
        .packet_type = SECURE_BLE_PKT_TYPE_READY_ACK,
        .packet_id = 0x02,
        .payload_size = 0x0000,
        .payload_type = SECURE_BLE_PAYLOAD_TYPE_UNDEFINED,
        .total_chunk = 0x01,
        .chunk_index = 0x00,
    };

    memset(ready_ack_packet.iv, 0, SECURE_BLE_IV_SIZE);
    memset(ready_ack_packet.tag, 0, SECURE_BLE_TAG_SIZE);
    memset(ready_ack_packet.payload_data, 0, SECURE_BLE_PAYLOAD_DATA_SIZE);
    memset(ready_ack_packet.checksum, 0, SECURE_BLE_CHECKSUM_SIZE);
    uint32_t crc = esp_rom_crc32_le(0, (uint8_t *)&ready_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE - SECURE_BLE_CHECKSUM_SIZE);
    memcpy(ready_ack_packet.checksum, &crc, SECURE_BLE_CHECKSUM_SIZE);
    // ESP_LOG_BUFFER_HEXDUMP("READY_ACK struct", (uint8_t*)&ready_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);
    *ready_packet_buffer = (uint8_t *)malloc(SECURE_BLE_TOTAL_PKT_SIZE);
    if (!*ready_packet_buffer)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Unable to allocate memory for ready packet buffer");
        return -1;
    }

    memset(*ready_packet_buffer, 0, SECURE_BLE_TOTAL_PKT_SIZE);
    memcpy(*ready_packet_buffer, (uint8_t *)&ready_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE);
    // ESP_LOG_BUFFER_HEXDUMP("READY_ACK buffer", *ready_packet_buffer, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);
    return 0;
}

int ble_secure_session_prepare_cli_pub_key_status_packet(uint8_t **cli_pub_key_status_packet_buffer, uint16_t cli_pub_key_status)
{
    s_secure_ble_packet_structure_t cli_pub_key_status_ack_packet = {
        .packet_type = SECURE_BLE_PKT_TYPE_CLI_PUB_KEY_STATUS,
        .packet_id = 0x04,
        .payload_size = 0x0002,
        .payload_type = SECURE_BLE_PAYLOAD_TYPE_UNDEFINED,
        .total_chunk = 0x01,
        .chunk_index = 0x00,
    };

    memset(cli_pub_key_status_ack_packet.iv, 0, SECURE_BLE_IV_SIZE);
    memset(cli_pub_key_status_ack_packet.tag, 0, SECURE_BLE_TAG_SIZE);
    memset(cli_pub_key_status_ack_packet.payload_data, 0, SECURE_BLE_PAYLOAD_DATA_SIZE);

    memcpy(cli_pub_key_status_ack_packet.payload_data, &cli_pub_key_status, 2);

    memset(cli_pub_key_status_ack_packet.checksum, 0, SECURE_BLE_CHECKSUM_SIZE);
    uint32_t crc = esp_rom_crc32_le(0, (uint8_t *)&cli_pub_key_status_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE - SECURE_BLE_CHECKSUM_SIZE);
    memcpy(cli_pub_key_status_ack_packet.checksum, &crc, SECURE_BLE_CHECKSUM_SIZE);
    ESP_LOG_BUFFER_HEXDUMP("READY_ACK struct", (uint8_t *)&cli_pub_key_status_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);

    *cli_pub_key_status_packet_buffer = (uint8_t *)malloc(SECURE_BLE_TOTAL_PKT_SIZE);
    if (!*cli_pub_key_status_packet_buffer)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Unable to allocate memory for cli pub key status packet buffer");
        return -1;
    }

    memset(*cli_pub_key_status_packet_buffer, 0, SECURE_BLE_TOTAL_PKT_SIZE);
    memcpy(*cli_pub_key_status_packet_buffer, (uint8_t *)&cli_pub_key_status_ack_packet, SECURE_BLE_TOTAL_PKT_SIZE);
    ESP_LOG_BUFFER_HEXDUMP("READY_ACK buffer", *cli_pub_key_status_packet_buffer, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);
    return 0;
}

int ble_secure_session_prepare_srv_pub_key_res_packet(uint8_t **srv_pub_key_packet_buffer, uint8_t srv_pub_key[65])
{
    s_secure_ble_packet_structure_t srv_pub_key_res_packet = {
        .packet_type = SECURE_BLE_PKT_TYPE_SRV_PUB_KEY_RES,
        .packet_id = 0x06,
        .payload_size = 0x0041,
        .payload_type = SECURE_BLE_PAYLOAD_TYPE_UNDEFINED,
        .total_chunk = 0x01,
        .chunk_index = 0x00,
    };

    memset(srv_pub_key_res_packet.iv, 0, SECURE_BLE_IV_SIZE);
    memset(srv_pub_key_res_packet.tag, 0, SECURE_BLE_TAG_SIZE);
    memset(srv_pub_key_res_packet.payload_data, 0, SECURE_BLE_PAYLOAD_DATA_SIZE);

    memcpy(srv_pub_key_res_packet.payload_data, srv_pub_key, 65);

    memset(srv_pub_key_res_packet.checksum, 0, SECURE_BLE_CHECKSUM_SIZE);
    uint32_t crc = esp_rom_crc32_le(0, (uint8_t *)&srv_pub_key_res_packet, SECURE_BLE_TOTAL_PKT_SIZE - SECURE_BLE_CHECKSUM_SIZE);
    memcpy(srv_pub_key_res_packet.checksum, &crc, SECURE_BLE_CHECKSUM_SIZE);
    ESP_LOG_BUFFER_HEXDUMP("READY_ACK struct", (uint8_t *)&srv_pub_key_res_packet, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);

    *srv_pub_key_packet_buffer = (uint8_t *)malloc(SECURE_BLE_TOTAL_PKT_SIZE);
    if (!*srv_pub_key_packet_buffer)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Unable to allocate memory for srv pub key response packet buffer");
        return -1;
    }

    memset(*srv_pub_key_packet_buffer, 0, SECURE_BLE_TOTAL_PKT_SIZE);
    memcpy(*srv_pub_key_packet_buffer, (uint8_t *)&srv_pub_key_res_packet, SECURE_BLE_TOTAL_PKT_SIZE);
    ESP_LOG_BUFFER_HEXDUMP("READY_ACK buffer", *srv_pub_key_packet_buffer, SECURE_BLE_TOTAL_PKT_SIZE, ESP_LOG_ERROR);
    return 0;
}

static int ble_secure_session_prepare_data_packet(uint8_t **data_packet_buffer,
                                                  ble_secure_payload_type_t payload_type,
                                                  uint8_t *data,
                                                  size_t data_len,
                                                  uint8_t total_chunk,
                                                  uint8_t chunk_index,
                                                  uint8_t iv[SECURE_BLE_IV_SIZE],
                                                  uint8_t tag[SECURE_BLE_TAG_SIZE])
{
    if (0 == data_len || data_len > SECURE_BLE_PAYLOAD_DATA_SIZE)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Invalid payload len(data_len: %d)", data_len);
        return -1;
    }

    if (!data)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Empty data passed");
        return -1;
    }

    if (*data_packet_buffer)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Data packet buffer should be null");
        return -1;
    }

    s_secure_ble_packet_structure_t data_packet = {
        .packet_type = SECURE_BLE_PKT_TYPE_DATA,
        .packet_id = 0x08,
        .payload_size = data_len,
        .payload_type = payload_type,
        .total_chunk = total_chunk,
        .chunk_index = chunk_index,
    };

    memset(data_packet.iv, 0, SECURE_BLE_IV_SIZE);
    memcpy(data_packet.iv, iv, SECURE_BLE_IV_SIZE);

    memset(data_packet.tag, 0, SECURE_BLE_TAG_SIZE);
    memcpy(data_packet.tag, tag, SECURE_BLE_TAG_SIZE);

    memset(data_packet.payload_data, 0, SECURE_BLE_PAYLOAD_DATA_SIZE);
    memcpy(data_packet.payload_data, data, data_len);

    memset(data_packet.checksum, 0, SECURE_BLE_CHECKSUM_SIZE);
    uint32_t crc = esp_rom_crc32_le(0, (uint8_t *)&data_packet, SECURE_BLE_TOTAL_PKT_SIZE - SECURE_BLE_CHECKSUM_SIZE);
    memcpy(data_packet.checksum, &crc, SECURE_BLE_CHECKSUM_SIZE);

    *data_packet_buffer = (uint8_t *)malloc(SECURE_BLE_TOTAL_PKT_SIZE);
    if (!*data_packet_buffer)
    {
        ESP_LOGE(BLE_SECURE_SERVICE_PKT_TAG, "Unable to allocate memory for data packet buffer");
        return -1;
    }

    memset(*data_packet_buffer, 0, SECURE_BLE_TOTAL_PKT_SIZE);
    memcpy(*data_packet_buffer, &data_packet, SECURE_BLE_TOTAL_PKT_SIZE);
    return 0;
}

int ble_secure_session_prepare_wifi_data_payload_packet(uint8_t **wifi_payload_packet_buffer, uint8_t ssid[32], uint8_t psk[32])
{
    uint8_t wifi_data_buffer[64];
    memcpy(wifi_data_buffer, ssid, 32);
    memcpy(wifi_data_buffer + 32, psk, 32);
    return 0;
}
