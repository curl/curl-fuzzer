# nghttp3 APIs whose connection-state contract is enforced by the link shim.
# Keep this list in sync with nghttp3_contract_shim.cc. The symbol-surface
# audit rejects new nghttp3 calls until they are classified here.
set(NGHTTP3_CONTRACT_WRAPPED_APIS
    nghttp3_conn_add_ack_offset
    nghttp3_conn_add_write_offset
    nghttp3_conn_bind_control_stream
    nghttp3_conn_bind_qpack_streams
    nghttp3_conn_block_stream
    nghttp3_conn_client_new_versioned
    nghttp3_conn_close_stream
    nghttp3_conn_close_stream2
    nghttp3_conn_del
    nghttp3_conn_read_stream
    nghttp3_conn_read_stream2
    nghttp3_conn_resume_stream
    nghttp3_conn_server_new_versioned
    nghttp3_conn_set_max_concurrent_streams
    nghttp3_conn_set_stream_user_data
    nghttp3_conn_shutdown_stream_read
    nghttp3_conn_shutdown_stream_write
    nghttp3_conn_submit_info
    nghttp3_conn_submit_request
    nghttp3_conn_submit_response
    nghttp3_conn_submit_trailers
    nghttp3_conn_unblock_stream
    nghttp3_conn_writev_stream)

# Current nghttp3 APIs used by libcurl or the HTTP/3 peer that do not operate
# on an nghttp3_conn. Future calls must be added here or wrapped above.
set(NGHTTP3_CONTRACT_ALLOWED_APIS
    nghttp3_err_infer_quic_app_error_code
    nghttp3_rcbuf_get_buf
    nghttp3_settings_default_versioned
    nghttp3_strerror
    nghttp3_version)
