
#include "esp_log.h"

#include "ble.h"

#define TAG __FILE__

void ble_services_wifi_service_callback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    switch (event)
    {
    case ESP_GATTS_READ_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_READ_EVT");
        break;
    }
    case ESP_GATTS_WRITE_EVT:
    {
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT");
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
