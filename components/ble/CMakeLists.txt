
set(
    SERVICE_CALLBACKS 
    "service_callbacks/ble_wifi_service.c"
)

idf_component_register(SRCS "ble_gatts.c" "ble.c" "ble_gap.c" ${SERVICE_CALLBACKS}
                        INCLUDE_DIRS .
                        REQUIRES bt
)

