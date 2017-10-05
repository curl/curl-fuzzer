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
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL API into making a request.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz;
  TLV tlv;

  /* Have to set all fields to zero before getting to the terminate function */
  memset(&fuzz, 0, sizeof(FUZZ_DATA));

  if(size < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Try to initialize the fuzz data */
  FTRY(fuzz_initialize_fuzz_data(&fuzz, data, size));

  for(tlv_rc = fuzz_get_first_tlv(&fuzz, &tlv);
      tlv_rc == 0;
      tlv_rc = fuzz_get_next_tlv(&fuzz, &tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_tlv(&fuzz, &tlv);

    if(rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if(tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

  /**
   * Add in more curl options that have been accumulated over possibly
   * multiple TLVs.
   */
  if(fuzz.header_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_HTTPHEADER, fuzz.header_list);
  }

  if(fuzz.mail_recipients_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MAIL_RCPT, fuzz.mail_recipients_list);
  }

  if(fuzz.mime != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MIMEPOST, fuzz.mime);
  }

  /* Run the transfer. */
  fuzz_handle_transfer(&fuzz);

EXIT_LABEL:

  fuzz_terminate_fuzz_data(&fuzz);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}

/**
 * Utility function to convert 4 bytes to a u32 predictably.
 */
uint32_t to_u32(const uint8_t b[4])
{
  uint32_t u;
  u = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
  return u;
}

/**
 * Utility function to convert 2 bytes to a u16 predictably.
 */
uint16_t to_u16(const uint8_t b[2])
{
  uint16_t u;
  u = (b[0] << 8) + b[1];
  return u;
}

/**
 * Initialize the local fuzz data structure.
 */
int fuzz_initialize_fuzz_data(FUZZ_DATA *fuzz,
                              const uint8_t *data,
                              size_t data_len)
{
  int rc = 0;

  /* Initialize the fuzz data. */
  memset(fuzz, 0, sizeof(FUZZ_DATA));

  /* Create an easy handle. This will have all of the settings configured on
     it. */
  fuzz->easy = curl_easy_init();
  FCHECK(fuzz->easy != NULL);

  /* Set some standard options on the CURL easy handle. We need to override the
     socket function so that we create our own sockets to present to CURL. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_OPENSOCKETFUNCTION,
                        fuzz_open_socket));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETDATA, fuzz));

  /* In case something tries to set a socket option, intercept this. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_SOCKOPTFUNCTION,
                        fuzz_sockopt_callback));

  /* Set the standard read function callback. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_READFUNCTION,
                        fuzz_read_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READDATA, fuzz));

  /* Set the standard write function callback. */
  FTRY(curl_easy_setopt(fuzz->easy,
                        CURLOPT_WRITEFUNCTION,
                        fuzz_write_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_WRITEDATA, fuzz));

  /* Set the cookie jar so cookies are tested. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_COOKIEJAR, FUZZ_COOKIE_JAR_PATH));

  /* Time out requests quickly. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_TIMEOUT_MS, 200L));

  /* Can enable verbose mode by having the environment variable FUZZ_VERBOSE. */
  if (getenv("FUZZ_VERBOSE") != NULL)
  {
    FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 1L));
  }

  /* Set up the state parser */
  fuzz->state.data = data;
  fuzz->state.data_len = data_len;

  /* Set up the state of the server socket. */
  fuzz->server_fd_state = FUZZ_SOCK_CLOSED;

EXIT_LABEL:

  return rc;
}

/**
 * Terminate the fuzz data structure, including freeing any allocated memory.
 */
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz)
{
  fuzz_free((void **)&fuzz->url);
  fuzz_free((void **)&fuzz->username);
  fuzz_free((void **)&fuzz->password);
  fuzz_free((void **)&fuzz->postfields);
  fuzz_free((void **)&fuzz->cookie);
  fuzz_free((void **)&fuzz->range);
  fuzz_free((void **)&fuzz->customrequest);
  fuzz_free((void **)&fuzz->mail_from);

  if(fuzz->server_fd_state != FUZZ_SOCK_CLOSED){
    close(fuzz->server_fd);
    fuzz->server_fd_state = FUZZ_SOCK_CLOSED;
  }

  if(fuzz->header_list != NULL) {
    curl_slist_free_all(fuzz->header_list);
    fuzz->header_list = NULL;
  }

  if(fuzz->mail_recipients_list != NULL) {
    curl_slist_free_all(fuzz->mail_recipients_list);
    fuzz->mail_recipients_list = NULL;
  }

  if(fuzz->mime != NULL) {
    curl_mime_free(fuzz->mime);
    fuzz->mime = NULL;
  }

  if(fuzz->easy != NULL) {
    curl_easy_cleanup(fuzz->easy);
    fuzz->easy = NULL;
  }
}

/**
 * If a pointer has been allocated, free that pointer.
 */
void fuzz_free(void **ptr)
{
  if(*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  }
}

/**
 * Function for providing a socket to CURL already primed with data.
 */
static curl_socket_t fuzz_open_socket(void *ptr,
                                      curlsocktype purpose,
                                      struct curl_sockaddr *address)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  int fds[2];
  curl_socket_t client_fd;
  int flags;
  int status;
  const uint8_t *data;
  size_t data_len;

  /* Handle unused parameters */
  (void)purpose;
  (void)address;

  if(fuzz->server_fd_state != FUZZ_SOCK_CLOSED) {
    /* A socket has already been opened. */
    return CURL_SOCKET_BAD;
  }

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    /* Failed to create a pair of sockets. */
    return CURL_SOCKET_BAD;
  }

  fuzz->server_fd = fds[0];
  client_fd = fds[1];

  /* Make the server non-blocking. */
  flags = fcntl(fuzz->server_fd, F_GETFL, 0);
  status = fcntl(fuzz->server_fd, F_SETFL, flags | O_NONBLOCK);

  if(status == -1) {
    /* Setting non-blocking failed. Return a negative response code. */
    return CURL_SOCKET_BAD;
  }

  fuzz->server_fd_state = FUZZ_SOCK_OPEN;

  /* If the server should be sending data immediately, send it here. */
  data = fuzz->responses[0].data;
  data_len = fuzz->responses[0].data_len;

  if(data != NULL) {
    if(write(fuzz->server_fd, data, data_len) != (ssize_t)data_len) {
      /* Failed to write all of the response data. */
      return CURL_SOCKET_BAD;
    }
  }

  /* Check to see if the socket should be shut down immediately. */
  if(fuzz->responses[1].data == NULL) {
    shutdown(fuzz->server_fd, SHUT_WR);
    fuzz->server_fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  return client_fd;
}

/**
 * Callback function for setting socket options on the sockets created by
 * fuzz_open_socket. In our testbed the sockets are "already connected".
 */
static int fuzz_sockopt_callback(void *ptr,
                                 curl_socket_t curlfd,
                                 curlsocktype purpose)
{
  (void)ptr;
  (void)curlfd;
  (void)purpose;

  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/**
 * Callback function for doing data uploads.
 */
static size_t fuzz_read_callback(char *buffer,
                                 size_t size,
                                 size_t nitems,
                                 void *ptr)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  size_t remaining_data;

  /* If no upload data has been specified, then return an error code. */
  if(fuzz->upload1_data_len == 0) {
    /* No data to upload */
    return CURL_READFUNC_ABORT;
  }

  /* Work out how much data is remaining to upload. */
  remaining_data = fuzz->upload1_data_len - fuzz->upload1_data_written;

  if(remaining_data > 0) {
    /* Send the upload data. */
    memcpy(&buffer[fuzz->upload1_data_written],
           fuzz->upload1_data,
           remaining_data);

    /* Increase the count of written data */
    fuzz->upload1_data_written += remaining_data;
  }

  return(remaining_data);
}

/**
 * Callback function for handling data output quietly.
 */
static size_t fuzz_write_callback(void *contents,
                                  size_t size,
                                  size_t nmemb,
                                  void *ptr)
{
  size_t total = size * nmemb;
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  size_t copy_len = total;

  /* Restrict copy_len to at most TEMP_WRITE_ARRAY_SIZE. */
  if(copy_len > TEMP_WRITE_ARRAY_SIZE) {
    copy_len = TEMP_WRITE_ARRAY_SIZE;
  }

  /* Copy bytes to the temp store just to ensure the parameters are
     exercised. */
  memcpy(fuzz->write_array, contents, copy_len);

  return total;
}

/**
 * TLV access function - gets the first TLV from a data stream.
 */
int fuzz_get_first_tlv(FUZZ_DATA *fuzz,
                       TLV *tlv)
{
  /* Reset the cursor. */
  fuzz->state.data_pos = 0;
  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * TLV access function - gets the next TLV from a data stream.
*/
int fuzz_get_next_tlv(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  /* Advance the cursor by the full length of the previous TLV. */
  fuzz->state.data_pos += sizeof(TLV_RAW) + tlv->length;

  /* Work out if there's a TLV's worth of data to read */
  if(fuzz->state.data_pos + sizeof(TLV_RAW) > fuzz->state.data_len) {
    /* No more TLVs to parse */
    return TLV_RC_NO_MORE_TLVS;
  }

  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * Common TLV function for accessing TLVs in a data stream.
 */
int fuzz_get_tlv_comn(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  int rc = 0;
  size_t data_offset;
  TLV_RAW *raw;

  /* Start by casting the data stream to a TLV. */
  raw = (TLV_RAW *)&fuzz->state.data[fuzz->state.data_pos];
  data_offset = fuzz->state.data_pos + sizeof(TLV_RAW);

  /* Set the TLV values. */
  tlv->type = to_u16(raw->raw_type);
  tlv->length = to_u32(raw->raw_length);
  tlv->value = &fuzz->state.data[data_offset];

  /* Sanity check that the TLV length is ok. */
  if(data_offset + tlv->length > fuzz->state.data_len) {
    rc = TLV_RC_SIZE_ERROR;
  }

  return rc;
}

/**
 * Do different actions on the CURL handle for different received TLVs.
 */
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv)
{
  int rc;
  char *tmp;
  uint32_t tmp_u32;

  switch(tlv->type) {
    /* The pointers in response TLVs will always be valid as long as the fuzz
       data is in scope, which is the entirety of this file. */
    FRESPONSETLV(TLV_TYPE_RESPONSE0, 0);
    FRESPONSETLV(TLV_TYPE_RESPONSE1, 1);
    FRESPONSETLV(TLV_TYPE_RESPONSE2, 2);
    FRESPONSETLV(TLV_TYPE_RESPONSE3, 3);
    FRESPONSETLV(TLV_TYPE_RESPONSE4, 4);
    FRESPONSETLV(TLV_TYPE_RESPONSE5, 5);
    FRESPONSETLV(TLV_TYPE_RESPONSE6, 6);
    FRESPONSETLV(TLV_TYPE_RESPONSE7, 7);
    FRESPONSETLV(TLV_TYPE_RESPONSE8, 8);
    FRESPONSETLV(TLV_TYPE_RESPONSE9, 9);
    FRESPONSETLV(TLV_TYPE_RESPONSE10, 10);

    case TLV_TYPE_UPLOAD1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */
      fuzz->upload1_data = tlv->value;
      fuzz->upload1_data_len = tlv->length;

      curl_easy_setopt(fuzz->easy, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(fuzz->easy,
                       CURLOPT_INFILESIZE_LARGE,
                       (curl_off_t)fuzz->upload1_data_len);
      break;

    case TLV_TYPE_HEADER:
      tmp = fuzz_tlv_to_string(tlv);
      fuzz->header_list = curl_slist_append(fuzz->header_list, tmp);
      fuzz_free((void **)&tmp);
      break;

    case TLV_TYPE_MAIL_RECIPIENT:
      tmp = fuzz_tlv_to_string(tlv);
      fuzz->mail_recipients_list =
                             curl_slist_append(fuzz->mail_recipients_list, tmp);
      fuzz_free((void **)&tmp);
      break;

    case TLV_TYPE_MIME_PART:
      if(fuzz->mime == NULL) {
        fuzz->mime = curl_mime_init(fuzz->easy);
      }

      fuzz->part = curl_mime_addpart(fuzz->mime);
      break;

    /* Define a set of u32 options. */
    FU32TLV(TLV_TYPE_HTTPAUTH, CURLOPT_HTTPAUTH);
    FU32TLV(TLV_TYPE_OPTHEADER, CURLOPT_HEADER);
    FU32TLV(TLV_TYPE_NOBODY, CURLOPT_NOBODY);

    /* Define a set of singleton TLVs - they can only have their value set once
       and all follow the same pattern. */
    FSINGLETONTLV(TLV_TYPE_URL, url, CURLOPT_URL);
    FSINGLETONTLV(TLV_TYPE_USERNAME, username, CURLOPT_USERNAME);
    FSINGLETONTLV(TLV_TYPE_PASSWORD, password, CURLOPT_PASSWORD);
    FSINGLETONTLV(TLV_TYPE_POSTFIELDS, postfields, CURLOPT_POSTFIELDS);
    FSINGLETONTLV(TLV_TYPE_COOKIE, cookie, CURLOPT_COOKIE);
    FSINGLETONTLV(TLV_TYPE_RANGE, range, CURLOPT_RANGE);
    FSINGLETONTLV(TLV_TYPE_CUSTOMREQUEST, customrequest, CURLOPT_CUSTOMREQUEST);
    FSINGLETONTLV(TLV_TYPE_MAIL_FROM, mail_from, CURLOPT_MAIL_FROM);

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 255;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  return rc;
}

/**
 * Converts a TLV data and length into an allocated string.
 */
char *fuzz_tlv_to_string(TLV *tlv)
{
  char *tlvstr;

  /* Allocate enough space, plus a null terminator */
  tlvstr = (char *)malloc(tlv->length + 1);

  if(tlvstr != NULL) {
    memcpy(tlvstr, tlv->value, tlv->length);
    tlvstr[tlv->length] = 0;
  }

  return tlvstr;
}

/**
 * Extract the values from the TLV.
 */
int fuzz_add_mime_part(TLV *src_tlv, curl_mimepart *part)
{
  FUZZ_DATA part_fuzz;
  TLV tlv;
  int rc = 0;
  int tlv_rc;

  memset(&part_fuzz, 0, sizeof(FUZZ_DATA));

  if(src_tlv->length < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Set up the state parser */
  part_fuzz.state.data = src_tlv->value;
  part_fuzz.state.data_len = src_tlv->length;

  for(tlv_rc = fuzz_get_first_tlv(&part_fuzz, &tlv);
      tlv_rc == 0;
      tlv_rc = fuzz_get_next_tlv(&part_fuzz, &tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_mime_tlv(part, &tlv);

    if(rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if(tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

EXIT_LABEL:

  return(rc);
}

/**
 * Do different actions on the mime part for different received TLVs.
 */
int fuzz_parse_mime_tlv(curl_mimepart *part, TLV *tlv)
{
  int rc;
  char *tmp;

  switch(tlv->type) {
    case TLV_TYPE_MIME_PART_NAME:
      tmp = fuzz_tlv_to_string(tlv);
      curl_mime_name(part, tmp);
      fuzz_free((void **)&tmp);
      break;

    case TLV_TYPE_MIME_PART_DATA:
      curl_mime_data(part, (const char *)tlv->value, tlv->length);
      break;

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 255;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  return rc;
}

/**
 * Function for handling the fuzz transfer, including sending responses to
 * requests.
 */
int fuzz_handle_transfer(FUZZ_DATA *fuzz)
{
  int rc = 0;
  CURLM *multi_handle;
  int still_running; /* keep number of running handles */
  CURLMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */
  int double_timeout = 0;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  struct timeval timeout;
  int select_rc;
  CURLMcode mc;
  int maxfd = -1;
  long curl_timeo = -1;

  /* Set up the starting index for responses. */
  fuzz->response_index = 1;

  /* init a multi stack */
  multi_handle = curl_multi_init();

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, fuzz->easy);

  do {
    /* Reset the sets of file descriptors. */
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* Set a timeout of 10ms. This is lower than recommended by the multi guide
       but we're not going to any remote servers, so everything should complete
       very quickly. */
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    /* get file descriptors from the transfers */
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      rc = -1;
      break;
    }

    /* Add the socket FD into the readable set if connected. */
    if(fuzz->server_fd_state == FUZZ_SOCK_OPEN) {
      FD_SET(fuzz->server_fd, &fdread);

      /* Work out the maximum FD between the cURL file descriptors and the
         server FD. */
      maxfd = (fuzz->server_fd > maxfd) ? fuzz->server_fd : maxfd;
    }

    /* Work out what file descriptors need work. */
    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if(rc == -1) {
      /* Had an issue while selecting a file descriptor. Let's just exit. */
      break;
    }
    else if(rc == 0) {
      /* Timed out. */
      if(double_timeout == 1) {
        /* We don't expect multiple timeouts in a row. If there are double
           timeouts then exit. */
        break;
      }
      else {
        /* Set the timeout flag for the next time we select(). */
        double_timeout = 1;
      }
    }
    else {
      /* There's an active file descriptor. Reset the timeout flag. */
      double_timeout = 0;
    }

    /* Check to see if the server file descriptor is readable. If it is,
       then send the next response from the fuzzing data. */
    if(fuzz->server_fd_state == FUZZ_SOCK_OPEN &&
       FD_ISSET(fuzz->server_fd, &fdread)) {
      rc = fuzz_send_next_response(fuzz);
      if(rc != 0) {
        /* Failed to send a response. Break out here. */
        break;
      }
    }

    /* Process the multi object. */
    curl_multi_perform(multi_handle, &still_running);

  } while(still_running);

  /* Clean up the multi handle - the top level function will handle the easy
     handle. */
  curl_multi_cleanup(multi_handle);

  return(rc);
}

/**
 * Sends the next fuzzing response to the server file descriptor.
 */
int fuzz_send_next_response(FUZZ_DATA *fuzz)
{
  int rc = 0;
  ssize_t ret_in;
  ssize_t ret_out;
  char buffer[8192];
  const uint8_t *data;
  size_t data_len;
  int is_verbose;

  /* Work out if we're tracing out. If we are, trace out the received data. */
  is_verbose = (getenv("FUZZ_VERBOSE") != NULL);

  /* Need to read all data sent by the client so the file descriptor becomes
     unreadable. Because the file descriptor is non-blocking we won't just
     hang here. */
  do {
    ret_in = read(fuzz->server_fd, buffer, sizeof(buffer));
    if(is_verbose && ret_in > 0) {
      printf("FUZZ: Received %zu bytes \n==>\n", ret_in);
      fwrite(buffer, ret_in, 1, stdout);
      printf("\n<==\n");
    }
  } while (ret_in > 0);

  /* Now send a response to the request that the client just made. */
  data = fuzz->responses[fuzz->response_index].data;
  data_len = fuzz->responses[fuzz->response_index].data_len;

  if(data != NULL) {
    if(write(fuzz->server_fd, data, data_len) != (ssize_t)data_len) {
      /* Failed to write the data back to the client. Prevent any further
         testing. */
      rc = -1;
    }
  }

  /* Work out if there are any more responses. If not, then shut down the
     server. */
  fuzz->response_index++;

  if(fuzz->response_index > TLV_MAX_NUM_RESPONSES ||
     fuzz->responses[fuzz->response_index].data == NULL) {
    shutdown(fuzz->server_fd, SHUT_WR);
    fuzz->server_fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  return(rc);
}