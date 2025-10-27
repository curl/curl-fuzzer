/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <inttypes.h>
#include <curl/curl.h>
#include "testinput.h"

/**
 * TLV types.
 */
#define TLV_TYPE_URL                            1
#define TLV_TYPE_RESPONSE0                      2
#define TLV_TYPE_USERNAME                       3
#define TLV_TYPE_PASSWORD                       4
#define TLV_TYPE_POSTFIELDS                     5
#define TLV_TYPE_HEADER                         6
#define TLV_TYPE_COOKIE                         7
#define TLV_TYPE_UPLOAD1                        8
#define TLV_TYPE_RANGE                          9
#define TLV_TYPE_CUSTOMREQUEST                  10
#define TLV_TYPE_MAIL_RECIPIENT                 11
#define TLV_TYPE_MAIL_FROM                      12
#define TLV_TYPE_MIME_PART                      13
#define TLV_TYPE_MIME_PART_NAME                 14
#define TLV_TYPE_MIME_PART_DATA                 15
#define TLV_TYPE_HTTPAUTH                       16
#define TLV_TYPE_RESPONSE1                      17
#define TLV_TYPE_RESPONSE2                      18
#define TLV_TYPE_RESPONSE3                      19
#define TLV_TYPE_RESPONSE4                      20
#define TLV_TYPE_RESPONSE5                      21
#define TLV_TYPE_RESPONSE6                      22
#define TLV_TYPE_RESPONSE7                      23
#define TLV_TYPE_RESPONSE8                      24
#define TLV_TYPE_RESPONSE9                      25
#define TLV_TYPE_RESPONSE10                     26
#define TLV_TYPE_OPTHEADER                      27
#define TLV_TYPE_NOBODY                         28
#define TLV_TYPE_FOLLOWLOCATION                 29
#define TLV_TYPE_ACCEPTENCODING                 30
#define TLV_TYPE_SECOND_RESPONSE0               31
#define TLV_TYPE_SECOND_RESPONSE1               32
#define TLV_TYPE_WILDCARDMATCH                  33
#define TLV_TYPE_RTSP_REQUEST                   34
#define TLV_TYPE_RTSP_SESSION_ID                35
#define TLV_TYPE_RTSP_STREAM_URI                36
#define TLV_TYPE_RTSP_TRANSPORT                 37
#define TLV_TYPE_RTSP_CLIENT_CSEQ               38
#define TLV_TYPE_MAIL_AUTH                      39
#define TLV_TYPE_HTTP_VERSION                   40
#define TLV_TYPE_DOH_URL                        41
#define TLV_TYPE_LOGIN_OPTIONS                  42
#define TLV_TYPE_XOAUTH2_BEARER                 43
#define TLV_TYPE_USERPWD                        44
#define TLV_TYPE_USERAGENT                      45
#define TLV_TYPE_NETRC                          46
#define TLV_TYPE_SSH_HOST_PUBLIC_KEY_SHA256     47
#define TLV_TYPE_POST                           48
#define TLV_TYPE_WS_OPTIONS                     49
#define TLV_TYPE_CONNECT_ONLY                   50
#define TLV_TYPE_HSTS                           51
#define TLV_TYPE_HTTPPOSTBODY                   52
#define TLV_TYPE_PROXY                          53
#define TLV_TYPE_PROXYTYPE                      54

#define TLV_TYPE_PROXYUSERPWD 100
#define TLV_TYPE_REFERER 101
#define TLV_TYPE_FTPPORT 102
#define TLV_TYPE_SSLCERT 103
#define TLV_TYPE_KEYPASSWD 104
#define TLV_TYPE_INTERFACE 105
#define TLV_TYPE_KRBLEVEL 106
#define TLV_TYPE_CAINFO 107
#define TLV_TYPE_SSL_CIPHER_LIST 108
#define TLV_TYPE_SSLCERTTYPE 109
#define TLV_TYPE_SSLKEY 110
#define TLV_TYPE_SSLKEYTYPE 111
#define TLV_TYPE_SSLENGINE 112
#define TLV_TYPE_CAPATH 113
#define TLV_TYPE_FTP_ACCOUNT 114
#define TLV_TYPE_COOKIELIST 115
#define TLV_TYPE_FTP_ALTERNATIVE_TO_USER 116
#define TLV_TYPE_SSH_PUBLIC_KEYFILE 117
#define TLV_TYPE_SSH_PRIVATE_KEYFILE 118
#define TLV_TYPE_SSH_HOST_PUBLIC_KEY_MD5 119
#define TLV_TYPE_ISSUERCERT 120
#define TLV_TYPE_PROXYUSERNAME 121
#define TLV_TYPE_PROXYPASSWORD 122
#define TLV_TYPE_NOPROXY 123
#define TLV_TYPE_SSH_KNOWNHOSTS 124
#define TLV_TYPE_TLSAUTH_USERNAME 125
#define TLV_TYPE_TLSAUTH_PASSWORD 126
#define TLV_TYPE_TLSAUTH_TYPE 127
#define TLV_TYPE_DNS_SERVERS 128
#define TLV_TYPE_DNS_INTERFACE 129
#define TLV_TYPE_DNS_LOCAL_IP4 130
#define TLV_TYPE_DNS_LOCAL_IP6 131
#define TLV_TYPE_PINNEDPUBLICKEY 132
#define TLV_TYPE_UNIX_SOCKET_PATH 133
#define TLV_TYPE_PROXY_SERVICE_NAME 134
#define TLV_TYPE_SERVICE_NAME 135
#define TLV_TYPE_DEFAULT_PROTOCOL 136
#define TLV_TYPE_PROXY_CAINFO 137
#define TLV_TYPE_PROXY_CAPATH 138
#define TLV_TYPE_PROXY_TLSAUTH_USERNAME 139
#define TLV_TYPE_PROXY_TLSAUTH_PASSWORD 140
#define TLV_TYPE_PROXY_TLSAUTH_TYPE 141
#define TLV_TYPE_PROXY_SSLCERT 142
#define TLV_TYPE_PROXY_SSLCERTTYPE 143
#define TLV_TYPE_PROXY_SSLKEY 144
#define TLV_TYPE_PROXY_SSLKEYTYPE 145
#define TLV_TYPE_PROXY_KEYPASSWD 146
#define TLV_TYPE_PROXY_SSL_CIPHER_LIST 147
#define TLV_TYPE_PROXY_CRLFILE 148
#define TLV_TYPE_PRE_PROXY 149
#define TLV_TYPE_PROXY_PINNEDPUBLICKEY 150
#define TLV_TYPE_ABSTRACT_UNIX_SOCKET 151
#define TLV_TYPE_REQUEST_TARGET 152
#define TLV_TYPE_TLS13_CIPHERS 153
#define TLV_TYPE_PROXY_TLS13_CIPHERS 154
#define TLV_TYPE_SASL_AUTHZID 155
#define TLV_TYPE_PROXY_ISSUERCERT 156
#define TLV_TYPE_SSL_EC_CURVES 157
#define TLV_TYPE_AWS_SIGV4 158
#define TLV_TYPE_REDIR_PROTOCOLS_STR 159
#define TLV_TYPE_HAPROXY_CLIENT_IP 160
#define TLV_TYPE_ECH 161

#define TLV_TYPE_PORT 200
#define TLV_TYPE_LOW_SPEED_LIMIT 201
#define TLV_TYPE_LOW_SPEED_TIME 202
#define TLV_TYPE_RESUME_FROM 203
#define TLV_TYPE_TIMEVALUE 204
#define TLV_TYPE_NOPROGRESS 205
#define TLV_TYPE_FAILONERROR 206
#define TLV_TYPE_DIRLISTONLY 207
#define TLV_TYPE_APPEND 208
#define TLV_TYPE_TRANSFERTEXT 209
#define TLV_TYPE_AUTOREFERER 210
#define TLV_TYPE_PROXYPORT 211
#define TLV_TYPE_POSTFIELDSIZE 212
#define TLV_TYPE_HTTPPROXYTUNNEL 213
#define TLV_TYPE_SSL_VERIFYPEER 214
#define TLV_TYPE_MAXREDIRS 215
#define TLV_TYPE_FILETIME 216
#define TLV_TYPE_MAXCONNECTS 217
#define TLV_TYPE_FRESH_CONNECT 218
#define TLV_TYPE_FORBID_REUSE 219
#define TLV_TYPE_CONNECTTIMEOUT 220
#define TLV_TYPE_HTTPGET 221
#define TLV_TYPE_SSL_VERIFYHOST 222
#define TLV_TYPE_FTP_USE_EPSV 223
#define TLV_TYPE_SSLENGINE_DEFAULT 224
#define TLV_TYPE_DNS_CACHE_TIMEOUT 225
#define TLV_TYPE_COOKIESESSION 226
#define TLV_TYPE_BUFFERSIZE 227
#define TLV_TYPE_NOSIGNAL 228
#define TLV_TYPE_UNRESTRICTED_AUTH 229
#define TLV_TYPE_FTP_USE_EPRT 230
#define TLV_TYPE_FTP_CREATE_MISSING_DIRS 231
#define TLV_TYPE_MAXFILESIZE 232
#define TLV_TYPE_TCP_NODELAY 233
#define TLV_TYPE_IGNORE_CONTENT_LENGTH 234
#define TLV_TYPE_FTP_SKIP_PASV_IP 235
#define TLV_TYPE_LOCALPORT 236
#define TLV_TYPE_LOCALPORTRANGE 237
#define TLV_TYPE_SSL_SESSIONID_CACHE 238
#define TLV_TYPE_FTP_SSL_CCC 239
#define TLV_TYPE_CONNECTTIMEOUT_MS 240
#define TLV_TYPE_HTTP_TRANSFER_DECODING 241
#define TLV_TYPE_HTTP_CONTENT_DECODING 242
#define TLV_TYPE_NEW_FILE_PERMS 243
#define TLV_TYPE_NEW_DIRECTORY_PERMS 244
#define TLV_TYPE_PROXY_TRANSFER_MODE 245
#define TLV_TYPE_ADDRESS_SCOPE 246
#define TLV_TYPE_CERTINFO 247
#define TLV_TYPE_TFTP_BLKSIZE 248
#define TLV_TYPE_SOCKS5_GSSAPI_NEC 249
#define TLV_TYPE_FTP_USE_PRET 250
#define TLV_TYPE_RTSP_SERVER_CSEQ 251
#define TLV_TYPE_TRANSFER_ENCODING 252
#define TLV_TYPE_ACCEPTTIMEOUT_MS 253
#define TLV_TYPE_TCP_KEEPALIVE 254
#define TLV_TYPE_TCP_KEEPIDLE 255
#define TLV_TYPE_TCP_KEEPINTVL 256
#define TLV_TYPE_SASL_IR 257
#define TLV_TYPE_SSL_ENABLE_ALPN 258
#define TLV_TYPE_EXPECT_100_TIMEOUT_MS 259
#define TLV_TYPE_SSL_VERIFYSTATUS 260
#define TLV_TYPE_SSL_FALSESTART 261
#define TLV_TYPE_PATH_AS_IS 262
#define TLV_TYPE_PIPEWAIT 263
#define TLV_TYPE_STREAM_WEIGHT 264
#define TLV_TYPE_TFTP_NO_OPTIONS 265
#define TLV_TYPE_TCP_FASTOPEN 266
#define TLV_TYPE_KEEP_SENDING_ON_ERROR 267
#define TLV_TYPE_PROXY_SSL_VERIFYPEER 268
#define TLV_TYPE_PROXY_SSL_VERIFYHOST 269
#define TLV_TYPE_PROXY_SSL_OPTIONS 270
#define TLV_TYPE_SUPPRESS_CONNECT_HEADERS 271
#define TLV_TYPE_SOCKS5_AUTH 272
#define TLV_TYPE_SSH_COMPRESSION 273
#define TLV_TYPE_HAPPY_EYEBALLS_TIMEOUT_MS 274
#define TLV_TYPE_HAPROXYPROTOCOL 275
#define TLV_TYPE_DNS_SHUFFLE_ADDRESSES 276
#define TLV_TYPE_DISALLOW_USERNAME_IN_URL 277
#define TLV_TYPE_UPLOAD_BUFFERSIZE 278
#define TLV_TYPE_UPKEEP_INTERVAL_MS 279
#define TLV_TYPE_HTTP09_ALLOWED 280
#define TLV_TYPE_ALTSVC_CTRL 281
#define TLV_TYPE_MAXAGE_CONN 282
#define TLV_TYPE_MAIL_RCPT_ALLOWFAILS 283
#define TLV_TYPE_HSTS_CTRL 284
#define TLV_TYPE_DOH_SSL_VERIFYPEER 285
#define TLV_TYPE_DOH_SSL_VERIFYHOST 286
#define TLV_TYPE_DOH_SSL_VERIFYSTATUS 287
#define TLV_TYPE_MAXLIFETIME_CONN 288
#define TLV_TYPE_MIME_OPTIONS 289
#define TLV_TYPE_CA_CACHE_TIMEOUT 290
#define TLV_TYPE_QUICK_EXIT 291
#define TLV_TYPE_SERVER_RESPONSE_TIMEOUT_MS 292
#define TLV_TYPE_TCP_KEEPCNT 293

#define TLV_TYPE_SSLVERSION 300
#define TLV_TYPE_TIMECONDITION 301
#define TLV_TYPE_PROXYAUTH 302
#define TLV_TYPE_IPRESOLVE 303
#define TLV_TYPE_USE_SSL 304
#define TLV_TYPE_FTPSSLAUTH 305
#define TLV_TYPE_FTP_FILEMETHOD 306
#define TLV_TYPE_SSH_AUTH_TYPES 307
#define TLV_TYPE_POSTREDIR 308
#define TLV_TYPE_GSSAPI_DELEGATION 309
#define TLV_TYPE_SSL_OPTIONS 310
#define TLV_TYPE_HEADEROPT 311
#define TLV_TYPE_PROXY_SSLVERSION 312

#define TLV_TYPE_RESUME_FROM_LARGE 320
#define TLV_TYPE_MAXFILESIZE_LARGE 321
#define TLV_TYPE_POSTFIELDSIZE_LARGE 322
#define TLV_TYPE_MAX_SEND_SPEED_LARGE 323
#define TLV_TYPE_MAX_RECV_SPEED_LARGE 324
#define TLV_TYPE_TIMEVALUE_LARGE 325

/**
 * TLV function return codes.
 */
#define TLV_RC_NO_ERROR                 0
#define TLV_RC_NO_MORE_TLVS             1
#define TLV_RC_SIZE_ERROR               2

/* Temporary write array size */
#define TEMP_WRITE_ARRAY_SIZE           10

/* Maximum write size in bytes to stop unbounded writes (50MB) */
#define MAXIMUM_WRITE_LENGTH            52428800

/* convenience string for HTTPPOST body name */
#define FUZZ_HTTPPOST_NAME              "test"

/* Cookie-jar WRITE (CURLOPT_COOKIEJAR) path. */
#define FUZZ_COOKIE_JAR_PATH            "/dev/null"

/* Cookie-jar READ (CURLOPT_COOKIEFILE) path. */
#define FUZZ_RO_COOKIE_FILE_PATH        "/dev/null"

/* Alt-Svc header cache path */
#define FUZZ_ALT_SVC_HEADER_CACHE_PATH  "/dev/null"

/* HSTS header cache path */
#define FUZZ_HSTS_HEADER_CACHE_PATH     "/dev/null"

/* Certificate Revocation List file path */
#define FUZZ_CRL_FILE_PATH              "/dev/null"

/* .netrc file path */
#define FUZZ_NETRC_FILE_PATH            "/dev/null"

/* Number of supported responses */
#define TLV_MAX_NUM_RESPONSES           11

/* Number of allowed CURLOPT_HEADERs */
#define TLV_MAX_NUM_CURLOPT_HEADER      2000

/* Space variable for all CURLOPTs. */
#define FUZZ_CURLOPT_TRACKER_SPACE      500

/* Number of connections allowed to be opened */
#define FUZZ_NUM_CONNECTIONS            2

typedef enum fuzz_sock_state {
  FUZZ_SOCK_CLOSED,
  FUZZ_SOCK_OPEN,
  FUZZ_SOCK_SHUTDOWN
} FUZZ_SOCK_STATE;

/**
 * Byte stream representation of the TLV header. Casting the byte stream
 * to a TLV_RAW allows us to examine the type and length.
 */
typedef struct tlv_raw
{
  /* Type of the TLV - 16 bits. */
  uint8_t raw_type[2];

  /* Length of the TLV data - 32 bits. */
  uint8_t raw_length[4];

} TLV_RAW;

typedef struct tlv
{
  /* Type of the TLV */
  uint16_t type;

  /* Length of the TLV data */
  uint32_t length;

  /* Pointer to data if length > 0. */
  const uint8_t *value;

} TLV;

/**
 * Internal state when parsing a TLV data stream.
 */
typedef struct fuzz_parse_state
{
  /* Data stream */
  const uint8_t *data;
  size_t data_len;

  /* Current position of our "cursor" in processing the data stream. */
  size_t data_pos;

} FUZZ_PARSE_STATE;

/**
 * Structure to use for responses.
 */
typedef struct fuzz_response
{
  /* Response data and length */
  const uint8_t *data;
  size_t data_len;

} FUZZ_RESPONSE;

typedef struct fuzz_socket_manager
{
  unsigned char index;

  /* Responses. Response 0 is sent as soon as the socket is connected. Further
     responses are sent when the socket becomes readable. */
  FUZZ_RESPONSE responses[TLV_MAX_NUM_RESPONSES];
  int response_index;

  /* Server file descriptor. */
  FUZZ_SOCK_STATE fd_state;
  curl_socket_t fd;

} FUZZ_SOCKET_MANAGER;

/**
 * Data local to a fuzzing run.
 */
typedef struct fuzz_data
{
  /* CURL easy object */
  CURL *easy;

  /* Parser state */
  FUZZ_PARSE_STATE state;

  /* Temporary writefunction state */
  char write_array[TEMP_WRITE_ARRAY_SIZE];

  /* Cumulative length of "written" data */
  size_t written_data;

  /* Upload data and length; */
  const uint8_t *upload1_data;
  size_t upload1_data_len;
  size_t upload1_data_written;

  /* Singleton option tracker. Options should only be set once. */
  unsigned char options[FUZZ_CURLOPT_TRACKER_SPACE];

  /* CURLOPT_POSTFIELDS data. */
  char *postfields;

  /* List of headers */
  int header_list_count;
  struct curl_slist *header_list;

  /* List of mail recipients */
  struct curl_slist *mail_recipients_list;

  /* List of connect_to strings */
  struct curl_slist *connect_to_list;

  /* Mime data */
  curl_mime *mime;
  curl_mimepart *part;

  /* httppost data */
  struct curl_httppost *httppost;
  struct curl_httppost *last_post_part;
  char *post_body;

  /* Server socket managers. Primarily socket manager 0 is used, but some
     protocols (FTP) use two sockets. */
  FUZZ_SOCKET_MANAGER sockman[FUZZ_NUM_CONNECTIONS];

  /* Verbose mode. */
  int verbose;

} FUZZ_DATA;

/* Function prototypes */
uint32_t to_u32(const uint8_t b[4]);
uint16_t to_u16(const uint8_t b[2]);
int fuzz_initialize_fuzz_data(FUZZ_DATA *fuzz,
                              const uint8_t *data,
                              size_t data_len);
int fuzz_set_easy_options(FUZZ_DATA *fuzz);
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz);
void fuzz_free(void **ptr);
curl_socket_t fuzz_open_socket(void *ptr,
                               curlsocktype purpose,
                               struct curl_sockaddr *address);
int fuzz_sockopt_callback(void *ptr,
                          curl_socket_t curlfd,
                          curlsocktype purpose);
size_t fuzz_read_callback(char *buffer,
                          size_t size,
                          size_t nitems,
                          void *ptr);
size_t fuzz_write_callback(void *contents,
                           size_t size,
                           size_t nmemb,
                           void *ptr);
int fuzz_get_first_tlv(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_get_next_tlv(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_get_tlv_comn(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv);
char *fuzz_tlv_to_string(TLV *tlv);
void fuzz_setup_http_post(FUZZ_DATA *fuzz, TLV *tlv);
int fuzz_add_mime_part(TLV *src_tlv, curl_mimepart *part);
int fuzz_parse_mime_tlv(curl_mimepart *part, TLV *tlv);
int fuzz_handle_transfer(FUZZ_DATA *fuzz);
int fuzz_send_next_response(FUZZ_DATA *fuzz, FUZZ_SOCKET_MANAGER *sockman);
int fuzz_select(int nfds,
                fd_set *readfds,
                fd_set *writefds,
                fd_set *exceptfds,
                struct timeval *timeout);
int fuzz_set_allowed_protocols(FUZZ_DATA *fuzz);

/* Macros */
#define FTRY(FUNC)                                                            \
        {                                                                     \
          int _func_rc = (FUNC);                                              \
          if (_func_rc)                                                       \
          {                                                                   \
            rc = _func_rc;                                                    \
            goto EXIT_LABEL;                                                  \
          }                                                                   \
        }

#define FCHECK(COND)                                                          \
        {                                                                     \
          if (!(COND))                                                        \
          {                                                                   \
            rc = 255;                                                         \
            goto EXIT_LABEL;                                                  \
          }                                                                   \
        }

#define FSET_OPTION(FUZZP, OPTNAME, OPTVALUE)                                 \
        FTRY(curl_easy_setopt((FUZZP)->easy, OPTNAME, OPTVALUE));             \
        (FUZZP)->options[OPTNAME % 1000] = 1

#define FCHECK_OPTION_UNSET(FUZZP, OPTNAME)                                   \
        FCHECK((FUZZP)->options[OPTNAME % 1000] == 0)

#define FSINGLETONTLV(FUZZP, TLVNAME, OPTNAME)                                \
        case TLVNAME:                                                         \
          FCHECK_OPTION_UNSET(FUZZP, OPTNAME);                                \
          tmp = fuzz_tlv_to_string(tlv);                                      \
          FSET_OPTION(FUZZP, OPTNAME, tmp);                                   \
          break

#define FRESPONSETLV(SMAN, TLVNAME, INDEX)                                    \
        case TLVNAME:                                                         \
          (SMAN)->responses[(INDEX)].data = tlv->value;                       \
          (SMAN)->responses[(INDEX)].data_len = tlv->length;                  \
          break

#define FU32TLV(FUZZP, TLVNAME, OPTNAME)                                      \
        case TLVNAME:                                                         \
          if(tlv->length != 4) {                                              \
            rc = 255;                                                         \
            goto EXIT_LABEL;                                                  \
          }                                                                   \
          FCHECK_OPTION_UNSET(FUZZP, OPTNAME);                                \
          tmp_u32 = to_u32(tlv->value);                                       \
          FSET_OPTION(FUZZP, OPTNAME, tmp_u32);                               \
          break

#define FV_PRINTF(FUZZP, ...)                                                 \
        if((FUZZP)->verbose) {                                                \
          printf(__VA_ARGS__);                                                \
        }

#define FUZZ_MAX(A, B) ((A) > (B) ? (A) : (B))
