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
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * Function for providing a socket to CURL already primed with data.
 */
curl_socket_t fuzz_open_socket(void *ptr,
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
    FV_PRINTF(fuzz, "FUZZ: Sending initial response \n");

    if(write(fuzz->server_fd, data, data_len) != (ssize_t)data_len) {
      /* Failed to write all of the response data. */
      return CURL_SOCKET_BAD;
    }
  }

  /* Check to see if the socket should be shut down immediately. */
  if(fuzz->responses[1].data == NULL) {
    FV_PRINTF(fuzz,
              "FUZZ: Shutting down server socket: %d \n",
              fuzz->server_fd);
    shutdown(fuzz->server_fd, SHUT_WR);
    fuzz->server_fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  return client_fd;
}

/**
 * Callback function for setting socket options on the sockets created by
 * fuzz_open_socket. In our testbed the sockets are "already connected".
 */
int fuzz_sockopt_callback(void *ptr,
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
size_t fuzz_read_callback(char *buffer,
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
size_t fuzz_write_callback(void *contents,
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
