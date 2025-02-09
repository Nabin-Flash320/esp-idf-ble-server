
#ifndef _BLE_H_
#define _BLE_H_

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"

#define BLE_GATTS_MAX_CHAR_LEN 5

#define BLE_SERVICE_SECURE_SESSION_UUID {           \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x76, 0x72, \
    0x65, 0x73, 0x0E, 0x00, 0x49, 0x54, 0x45, 0x59}

#define BLE_SERVICE_SECURE_SESSION_WRITE_CHAR_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x72, 0x61,  \
    0x68, 0x63, 0x01, 0xE0, 0x49, 0x54, 0x45, 0x59}
#define BLE_SERVICE_SECURE_SESSION_STATUS_CHAR_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x72, 0x61,   \
    0x68, 0x63, 0x02, 0xE0, 0x49, 0x54, 0x45, 0x59}
#define BLE_SERVICE_SECURE_SESSION_READ_CHAR_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x72, 0x61, \
    0x68, 0x63, 0x03, 0xE0, 0x49, 0x54, 0x45, 0x59}

#define BLE_SERVUCE_SECURE_SESSION_WRITE_CHAR_DESC_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x63, 0x73,       \
    0x65, 0x64, 0x01, 0xE1, 0x49, 0x54, 0x45, 0x59}
#define BLE_SERVUCE_SECURE_SESSION_STATUS_CHAR_DESC_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x63, 0x73,        \
    0x65, 0x64, 0x02, 0xE1, 0x49, 0x54, 0x45, 0x59}
#define BLE_SERVUCE_SECURE_SESSION_READ_CHAR_DESC_UUID { \
    0x22, 0xad, 0x6b, 0x84, 0xf4, 0xac, 0x63, 0x73,      \
    0x65, 0x64, 0x02, 0xE1, 0x49, 0x54, 0x45, 0x59}

typedef enum e_ble_profile_ids
{
    BLE_PROFILE_ID_SECURE_SESSION,
    BLE_PROFILE_ID_MAX,
} e_ble_profile_ids_t;

/* ==================== Security service enums ==================== */
typedef enum e_ble_service_security_char_ids
{
    BLE_SERVICE_SECURE_SESSION_CHAR_WRITE,
    BLE_SERVICE_SECURE_SESSION_CHAR_STATUS,
    BLE_SERVICE_SECURE_SESSION_CHAR_READ,
    BLE_SERVICE_SECURE_SESSION_CHAR_MAX,
} e_ble_service_security_char_ids_t;

/* ==================== BLE service structs ==================== */
typedef struct s_gatts_disc_inst
{
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
    esp_gatt_perm_t perm;
    esp_attr_value_t desc_val;
    esp_attr_control_t ctrl;
    bool added;
} s_gatts_disc_inst_t;

typedef struct s_gatts_char_inst
{
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint8_t descriptors_len;
    s_gatts_disc_inst_t *descriptors;
    uint8_t descriptors_added;
    bool added;
} s_gatts_char_inst_t;

typedef struct s_gatts_service_inst
{
    esp_gatts_cb_t gatts_cb;
    uint8_t gatts_if;
    uint16_t profile_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint8_t characteristics_len;
    s_gatts_char_inst_t *characteristics;
    uint8_t characteristics_added;
    uint8_t num_handle;
} s_gatts_service_inst_t;

void ble_init();
void ble_gap_start_ble_advertisement();
s_gatts_service_inst_t *ble_gap_get_service_instance_by_id(e_ble_profile_ids_t profile_id);
s_gatts_service_inst_t *ble_gap_get_service_instance_by_gatts_if(esp_gatt_if_t gatts_if);
s_gatts_service_inst_t *ble_gap_get_service_instance_by_service_handle(uint16_t service_handle);
void ble_gap_callbacak(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);
void ble_gatts_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

/*** ================================================================ Service callbacks definitions start ================================================================ ***/

void ble_services_security_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);
void ble_services_wifi_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

/*** ================================================================ Service callbacks definitions end ================================================================ ***/

#endif //  _BLE_H_
