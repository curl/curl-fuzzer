/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
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

#ifdef TLV_ENUM_BUFQ
#include "curl_fuzzer_tlv_bufq.h"
#else
#include "curl_fuzzer_tlv_main.h"
#endif

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
#define	FUZZ_HTTPPOST_NAME		"test"

/* Cookie-jar WRITE (CURLOPT_COOKIEJAR) path. */
#define FUZZ_COOKIE_JAR_PATH            "/dev/null"

/* Cookie-jar READ (CURLOPT_COOKIEFILE) path. */
#define FUZZ_RO_COOKIE_FILE_PATH	"/dev/null"

/* Alt-Svc header cache path */
#define FUZZ_ALT_SVC_HEADER_CACHE_PATH	"/dev/null"

/* HSTS header cache path */
#define FUZZ_HSTS_HEADER_CACHE_PATH 	"/dev/null"

/* Certificate Revocation List file path */
#define FUZZ_CRL_FILE_PATH		"/dev/null"

/* .netrc file path */
#define FUZZ_NETRC_FILE_PATH		"/dev/null"

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
 * Data local to a fuzzing run on the main fuzzer
 */
struct fuzz_data_main
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

};

/**
 * Data local to a fuzzing run on the BUFQ fuzzer
 */
struct fuzz_data_bufq
{
  /* Parser state */
  FUZZ_PARSE_STATE state;

  /* Verbose mode. */
  int verbose;
  
  int max_chunks;

  int chunk_size;

  int use_pool;

  int operation_count;

  int max_spare;
  
  int no_spare;

  struct fuzz_bufq_operation *operation_list;
};

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
int fuzz_handle_bufq(FUZZ_DATA *fuzz, unsigned char *template_buf);
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
