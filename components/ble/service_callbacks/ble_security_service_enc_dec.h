
#ifndef __BLE_SECURITY_SERVICE_ENC_DEC_H__
#define __BLE_SECURITY_SERVICE_ENC_DEC_H__

int ble_secure_session_generate_device_key_value_ecdh(uint8_t device_public_key[65], uint8_t device_private_key[32]);
int ble_secure_session_generate_shared_key(uint8_t client_public_key[65], uint8_t device_private_key[32], uint8_t shared_secret[32]);
int ble_secure_session_generate_session_key(uint8_t shared_secret[32], uint8_t session_key[32], uint8_t salt[32]);

#endif // __BLE_SECURITY_SERVICE_ENC_DEC_H__
