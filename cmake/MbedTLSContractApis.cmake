# Mbed TLS APIs whose connection-state contracts are enforced by the link shim.
set(MBEDTLS_CONTRACT_WRAPPED_APIS
    mbedtls_ssl_init
    mbedtls_ssl_free
    mbedtls_ssl_session_reset
    mbedtls_ssl_handshake
    mbedtls_ssl_read
    mbedtls_ssl_write
    mbedtls_ssl_close_notify)

# Current configuration and inspection APIs used by libcurl. New mbedtls_ssl_*
# calls must be added here or routed through the contract monitor.
set(MBEDTLS_CONTRACT_ALLOWED_APIS
    mbedtls_ssl_conf_alpn_protocols
    mbedtls_ssl_conf_authmode
    mbedtls_ssl_conf_ca_chain
    mbedtls_ssl_conf_cert_profile
    mbedtls_ssl_conf_ciphersuites
    mbedtls_ssl_conf_own_cert
    mbedtls_ssl_conf_renegotiation
    mbedtls_ssl_conf_session_tickets
    mbedtls_ssl_conf_verify
    mbedtls_ssl_config_defaults
    mbedtls_ssl_config_free
    mbedtls_ssl_config_init
    mbedtls_ssl_get_alpn_protocol
    mbedtls_ssl_get_bytes_avail
    mbedtls_ssl_get_ciphersuite_id_from_ssl
    mbedtls_ssl_get_ciphersuite_name
    mbedtls_ssl_get_peer_cert
    mbedtls_ssl_get_session
    mbedtls_ssl_get_version
    mbedtls_ssl_list_ciphersuites
    mbedtls_ssl_session_free
    mbedtls_ssl_session_init
    mbedtls_ssl_session_load
    mbedtls_ssl_session_save
    mbedtls_ssl_set_bio
    mbedtls_ssl_set_hostname
    mbedtls_ssl_set_session
    mbedtls_ssl_setup)
