
set(
    SERVICE_SRCS 
    "ble_gatts.c" 
    "ble.c" 
    "ble_gap.c"
    "service_callbacks/ble_secruity_service.c"
    "service_callbacks/ble_security_srv_pkt_handler.c"
    "service_callbacks/ble_security_service_enc_dec.c"
)

set(
    SERVICE_INCLUDES
    "."
    "service_callbacks"
)

idf_component_register(SRCS ${SERVICE_SRCS}
                        INCLUDE_DIRS ${SERVICE_INCLUDES}
                        REQUIRES bt mbedtls esp_event
)

