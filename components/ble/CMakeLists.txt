
idf_component_register(SRCS "ble_wifi_service.c" "ble_gatts.c" "ble.c" "ble_gap.c" 
                        INCLUDE_DIRS .
                        REQUIRES bt
)

