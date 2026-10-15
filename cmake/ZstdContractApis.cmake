# zstd APIs whose decompression-state contract is enforced by the link shim.
set(ZSTD_CONTRACT_WRAPPED_APIS
    ZSTD_createDCtx
    ZSTD_createDCtx_advanced
    ZSTD_createDStream
    ZSTD_createDStream_advanced
    ZSTD_freeDCtx
    ZSTD_freeDStream
    ZSTD_initDStream
    ZSTD_DCtx_reset
    ZSTD_decompressStream)

# Current context-free zstd APIs used by libcurl. The archive checks require
# every future ZSTD API to be classified as wrapped or safe.
set(ZSTD_CONTRACT_ALLOWED_APIS
    ZSTD_isError
    ZSTD_versionNumber)
