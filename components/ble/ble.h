
#ifndef _BLE_H_
#define _BLE_H_

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"

#define BLE_GATTS_MAX_CHAR_LEN 5

#define BLE_SERVICE_WIFI_UUID 0x00E1

#define BLE_SERVICE_WIFI_CHARACTERISTICS_ENABLE_WIFI_UUID 0xE101
#define BLE_SERVICE_WIFI_CHARACTERISTICS_GET_WIFI_UUID 0xE102
#define BLE_SERVICE_NAME_CHARACTERISTICS_SCAN_WIFI_UUID 0xE103
#define BLE_SERVICE_WIFI_CHARACTERISTICS_DISABLE_WIFI_UUID 0xE104

typedef enum e_ble_profile_ids
{
    BLE_PROFILE_ID_WIFI,
    BLE_PROFILE_ID_MAX,
} e_ble_profile_ids_t;

/* ==================== WiFi service enums ==================== */
typedef enum e_ble_service_wifi_char_ids
{
    BLE_SERVICE_WIFI_CHAR_ID_ENABLE_WIFI,
    BLE_SERVICE_WIFI_CHAR_ID_GET_WIFI_DETAILS,
    BLE_SERVICE_WIFI_CHAR_ID_SCAN_WIFI,
    BLE_SERVICE_WIFI_CHAR_ID_DISABLE_WIFI,
    BLE_SERVICE_WIFI_CHAR_ID_MAX,
} e_ble_service_wifi_char_ids_t;

/* ==================== BLE service structs ==================== */
typedef struct s_gatts_disc_inst
{
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
    esp_gatt_perm_t perm;
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
    uint16_t gatts_if;
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

void ble_services_wifi_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

/*** ================================================================ Service callbacks definitions end ================================================================ ***/

#endif //  _BLE_H_
