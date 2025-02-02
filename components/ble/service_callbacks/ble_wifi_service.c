
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
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT for handle: 0x%02x", param->write.handle);
        s_gatts_service_inst_t *service_instance = ble_gap_get_service_instance_by_gatts_if(gatts_if);
        if (service_instance)
        {
            ESP_LOGI(TAG, "Service handle: 0x%02x", service_instance->service_handle);
            for (int i = 0; i < service_instance->characteristics_len; i++)
            {
                ESP_LOGI(TAG, "\tCharacteristics handle: 0x%02x", service_instance->characteristics[i].char_handle);
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
