/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| | |
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/**
 * @file
 * @brief Loopback HTTP responder for the legacy DoH coverage lane.
 *
 * curl creates its internal DoH easy handle itself and does not propagate the
 * harness socketpair callbacks to it. A seed that sets TLV_TYPE_DOH_LOOPBACK
 * therefore gets a real plaintext HTTP listener on 127.0.0.1, and
 * CURLOPT_DOH_URL points at it. The listener synthesizes a DNS answer matching
 * the probe's QTYPE or serves a seed-supplied response body verbatim.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * No-op debug callback used by the verbose DoH lane. Turning on verbose makes
 * curl evaluate the arguments to infof(), which is what reaches the DoH
 * status/error string helpers. The callback keeps that tracing off stderr.
 */
int fuzz_doh_debug_callback(CURL *handle,
                            curl_infotype type,
                            char *data,
                            size_t size,
                            void *userptr)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)userptr;

  (void)handle;
  if(fuzz && fuzz->verbose && type == CURLINFO_TEXT && size)
    printf("FUZZ: DoH trace: %.*s", (int)size, data);
  (void)type;
  (void)data;
  (void)size;
  return 0;
}

/**
 * Reset the loopback DoH responder. FUZZ_DATA is memset twice (once before a
 * possible early exit and once inside fuzz_initialize_fuzz_data), so the
 * sentinel descriptors must be installed after each memset.
 */
void fuzz_doh_server_init(FUZZ_DATA *fuzz)
{
  int i;

  fuzz->doh.listener = CURL_SOCKET_BAD;
  fuzz->doh.enabled = 0;
  fuzz->doh.http_status = 200;
  fuzz->doh.response = NULL;
  fuzz->doh.response_len = 0;
  fuzz->doh.url[0] = '\0';
  fuzz->doh.saved_no_proxy_lower = NULL;
  fuzz->doh.saved_no_proxy_upper = NULL;
  fuzz->doh.lower_no_proxy_was_set = 0;
  fuzz->doh.upper_no_proxy_was_set = 0;
  fuzz->doh.proxy_bypass_active = 0;

  for(i = 0; i < FUZZ_DOH_MAX_CONNECTIONS; i++) {
    fuzz->doh.conns[i].fd = CURL_SOCKET_BAD;
    fuzz->doh.conns[i].state = FUZZ_DOH_CONN_FREE;
    fuzz->doh.conns[i].request_len = 0;
    fuzz->doh.conns[i].response_len = 0;
    fuzz->doh.conns[i].response_off = 0;
  }
}

static void fuzz_doh_conn_close(FUZZ_DOH_CONN *conn)
{
  if(conn->fd != CURL_SOCKET_BAD) {
    close(conn->fd);
    conn->fd = CURL_SOCKET_BAD;
  }
  conn->state = FUZZ_DOH_CONN_FREE;
  conn->request_len = 0;
  conn->response_len = 0;
  conn->response_off = 0;
}

/**
 * Bind a plaintext HTTP listener on 127.0.0.1 and build the CURLOPT_DOH_URL
 * value that points at it. The DoH sub-handle is created by curl and therefore
 * opens a real socket instead of the harness socketpair; a real loopback
 * endpoint is the only harness-side way to complete the probe.
 */
int fuzz_doh_server_start(FUZZ_DATA *fuzz)
{
  int fd;
  int flags;
  struct sockaddr_in addr;
  socklen_t addrlen;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0)
    return -1;
  if(fd >= FD_SETSIZE) {
    close(fd);
    return -1;
  }

  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }
  if(listen(fd, 8) < 0) {
    close(fd);
    return -1;
  }

  addrlen = sizeof(addr);
  if(getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0) {
    close(fd);
    return -1;
  }

  flags = fcntl(fd, F_GETFL, 0);
  if(flags < 0) {
    close(fd);
    return -1;
  }
  if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd);
    return -1;
  }

  fuzz->doh.listener = fd;
  snprintf(fuzz->doh.url, sizeof(fuzz->doh.url),
           "http://127.0.0.1:%d/dns-query", (int)ntohs(addr.sin_port));
  return 0;
}

/**
 * Copy one proxy environment variable so it can be restored after the input.
 * @return 0 on success, -1 when a set value could not be copied.
 */
static int fuzz_save_env(const char *name, char **copy, int *was_set)
{
  const char *value = getenv(name);
  size_t length;

  *copy = NULL;
  *was_set = 0;
  if(!value)
    return 0;

  length = strlen(value) + 1;
  *copy = (char *)malloc(length);
  if(!*copy)
    return -1;
  memcpy(*copy, value, length);
  *was_set = 1;
  return 0;
}

static void fuzz_free_saved_env(char **copy, int *was_set)
{
  free(*copy);
  *copy = NULL;
  *was_set = 0;
}

/**
 * Force NO_PROXY for the duration of a loopback input. The internal DoH easy
 * handle consults the process environment and does not inherit proxy options
 * from the parent transfer, so an ambient http_proxy/ALL_PROXY could divert
 * probes away from the listener and generate off-loopback traffic.
 */
void fuzz_doh_proxy_bypass_begin(FUZZ_DATA *fuzz)
{
  if(!fuzz->doh.enabled || fuzz->doh.proxy_bypass_active)
    return;

  if(fuzz_save_env("no_proxy", &fuzz->doh.saved_no_proxy_lower,
                   &fuzz->doh.lower_no_proxy_was_set) != 0 ||
     fuzz_save_env("NO_PROXY", &fuzz->doh.saved_no_proxy_upper,
                   &fuzz->doh.upper_no_proxy_was_set) != 0) {
    fuzz_free_saved_env(&fuzz->doh.saved_no_proxy_lower,
                        &fuzz->doh.lower_no_proxy_was_set);
    fuzz_free_saved_env(&fuzz->doh.saved_no_proxy_upper,
                        &fuzz->doh.upper_no_proxy_was_set);
    return;
  }

  /* Mark active before setenv so a partial failure is still restored. */
  fuzz->doh.proxy_bypass_active = 1;
  if(setenv("no_proxy", "*", 1) != 0 || setenv("NO_PROXY", "*", 1) != 0)
    fuzz_doh_proxy_bypass_end(fuzz);
  else
    FV_PRINTF(fuzz, "FUZZ: DoH proxy bypass enabled\n");
}

void fuzz_doh_proxy_bypass_end(FUZZ_DATA *fuzz)
{
  if(!fuzz->doh.proxy_bypass_active)
    return;

  if(fuzz->doh.lower_no_proxy_was_set)
    (void)setenv("no_proxy", fuzz->doh.saved_no_proxy_lower, 1);
  else
    (void)unsetenv("no_proxy");
  if(fuzz->doh.upper_no_proxy_was_set)
    (void)setenv("NO_PROXY", fuzz->doh.saved_no_proxy_upper, 1);
  else
    (void)unsetenv("NO_PROXY");

  fuzz_free_saved_env(&fuzz->doh.saved_no_proxy_lower,
                      &fuzz->doh.lower_no_proxy_was_set);
  fuzz_free_saved_env(&fuzz->doh.saved_no_proxy_upper,
                      &fuzz->doh.upper_no_proxy_was_set);
  fuzz->doh.proxy_bypass_active = 0;
  FV_PRINTF(fuzz, "FUZZ: DoH proxy bypass restored\n");
}

void fuzz_doh_server_stop(FUZZ_DATA *fuzz)
{
  int i;

  fuzz_doh_proxy_bypass_end(fuzz);

  if(fuzz->doh.listener != CURL_SOCKET_BAD) {
    close(fuzz->doh.listener);
    fuzz->doh.listener = CURL_SOCKET_BAD;
  }
  for(i = 0; i < FUZZ_DOH_MAX_CONNECTIONS; i++)
    fuzz_doh_conn_close(&fuzz->doh.conns[i]);
}

void fuzz_doh_server_add_fds(FUZZ_DATA *fuzz,
                             fd_set *readfds,
                             fd_set *writefds,
                             int *maxfd)
{
  int i;

  if(fuzz->doh.listener != CURL_SOCKET_BAD) {
    FD_SET(fuzz->doh.listener, readfds);
    *maxfd = FUZZ_MAX((int)fuzz->doh.listener, *maxfd);
  }

  for(i = 0; i < FUZZ_DOH_MAX_CONNECTIONS; i++) {
    FUZZ_DOH_CONN *conn = &fuzz->doh.conns[i];
    if(conn->fd == CURL_SOCKET_BAD)
      continue;
    if(conn->state == FUZZ_DOH_CONN_READING)
      FD_SET(conn->fd, readfds);
    else if(conn->state == FUZZ_DOH_CONN_WRITING)
      FD_SET(conn->fd, writefds);
    *maxfd = FUZZ_MAX((int)conn->fd, *maxfd);
  }
}

/**
 * Find the end of the HTTP headers and the Content-Length-delimited body.
 * @return 1 when a complete request is buffered, 0 when more bytes are needed,
 *         -1 when the request is too large or otherwise unusable.
 */
static int fuzz_doh_request_complete(FUZZ_DOH_CONN *conn,
                                     size_t *body_off,
                                     size_t *body_len)
{
  size_t i;
  size_t header_end = 0;
  size_t content_length = 0;
  int have_length = 0;

  for(i = 0; (i + 3) < conn->request_len; i++) {
    if(conn->request[i] == '\r' && conn->request[i + 1] == '\n' &&
       conn->request[i + 2] == '\r' && conn->request[i + 3] == '\n') {
      header_end = i + 4;
      break;
    }
  }
  if(!header_end)
    return 0;

  i = 0;
  while((i + 1) < header_end) {
    size_t line_end = i;
    while((line_end + 1) < header_end &&
          !(conn->request[line_end] == '\r' &&
            conn->request[line_end + 1] == '\n'))
      line_end++;

    if((line_end - i) > 15 &&
       !strncasecmp((const char *)&conn->request[i], "Content-Length:", 15)) {
      const char *value = (const char *)&conn->request[i + 15];
      char *end = NULL;
      unsigned long parsed = strtoul(value, &end, 10);
      if(end != value) {
        content_length = (size_t)parsed;
        have_length = 1;
      }
    }
    i = line_end + 2;
  }

  if(!have_length)
    content_length = conn->request_len - header_end;

  if(content_length > (sizeof(conn->request) - header_end))
    return -1;
  if(conn->request_len < (header_end + content_length))
    return 0;

  *body_off = header_end;
  *body_len = content_length;
  return 1;
}

/**
 * Synthesize a minimal DNS response matching the query's QTYPE. A and AAAA
 * answers point at loopback so the outer transfer can continue through the
 * existing socketpair mock. HTTPS queries get a minimal HTTPS RR so the
 * resolver's HTTPS-RR consume path is reachable. Other QTYPEs get NOTIMP.
 */
static size_t fuzz_doh_build_dns_response(const unsigned char *query,
                                          size_t query_len,
                                          unsigned char *resp,
                                          size_t resp_cap)
{
  size_t i = 12;
  size_t qname_end;
  unsigned short qtype;
  size_t question_len;
  size_t rdlength;
  size_t total;
  unsigned char *p;
  int has_answer;
  int answer_count;
  int n;

  if(query_len < 12)
    return 0;

  while(i < query_len) {
    unsigned char label = query[i];
    if(label == 0) {
      i++;
      break;
    }
    if(label & 0xc0)
      return 0;
    if((i + 1 + label) > query_len)
      return 0;
    i += (size_t)1 + label;
  }
  if((i + 4) > query_len)
    return 0;

  qname_end = i;
  qtype = (unsigned short)((query[qname_end] << 8) |
                           query[qname_end + 1]);
  question_len = (qname_end + 4) - 12;
  has_answer = (qtype == 1 || qtype == 28 || qtype == 65);
  rdlength = (qtype == 1) ? 4 : ((qtype == 28) ? 16 : 3);
  answer_count = (qtype == 65) ? 1 : (has_answer ? 2 : 0);
  total = 12 + question_len +
          ((size_t)answer_count * (12 + rdlength));

  if(total > resp_cap)
    return 0;

  memset(resp, 0, 12);
  resp[2] = 0x81; /* QR=1, RD=1 */
  resp[3] = has_answer ? 0x80 : 0x84; /* RA=1; rcode 4 for unsupported */
  resp[5] = 1; /* QDCOUNT */
  resp[7] = (unsigned char)answer_count; /* ANCOUNT */
  memcpy(&resp[12], &query[12], question_len);

  p = &resp[12 + question_len];
  for(n = 0; n < answer_count; n++) {
    *p++ = 0xc0; /* compressed name pointer to the question */
    *p++ = 0x0c;
    *p++ = (unsigned char)(qtype >> 8);
    *p++ = (unsigned char)(qtype & 0xff);
    *p++ = 0;
    *p++ = 1; /* CLASS IN */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 60; /* TTL */
    *p++ = 0;
    *p++ = (unsigned char)rdlength;
    if(qtype == 1) {
      *p++ = 127;
      *p++ = 0;
      *p++ = 0;
      *p++ = (unsigned char)(1 + n);
    }
    else if(qtype == 28) {
      memset(p, 0, 16);
      p[15] = (unsigned char)(1 + n); /* ::1, ::2 */
      p += 16;
    }
    else {
      /* Minimal HTTPS RR: priority 1, root target, no SvcParams. */
      *p++ = 0;
      *p++ = 1;
      *p++ = 0;
    }
  }

  return (size_t)(p - resp);
}

static int fuzz_doh_build_http_response(FUZZ_DATA *fuzz,
                                        FUZZ_DOH_CONN *conn,
                                        const unsigned char *body,
                                        size_t body_len)
{
  int header_len;

  header_len = snprintf((char *)conn->response, sizeof(conn->response),
                        "HTTP/1.1 %u DoH\r\n"
                        "Content-Type: application/dns-message\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        fuzz->doh.http_status, body_len);
  if(header_len < 0)
    return -1;
  if((size_t)header_len + body_len > sizeof(conn->response))
    return -1;

  if(body_len)
    memcpy(&conn->response[header_len], body, body_len);
  conn->response_len = (size_t)header_len + body_len;
  conn->response_off = 0;
  return 0;
}

/**
 * Accept pending probe connections and advance the small request/response
 * state machine. Called with the fd sets returned by select().
 */
int fuzz_doh_server_service(FUZZ_DATA *fuzz,
                            fd_set *readfds,
                            fd_set *writefds)
{
  int i;
  int progress = 0;

  if(fuzz->doh.listener != CURL_SOCKET_BAD &&
     FD_ISSET(fuzz->doh.listener, readfds)) {
    for(;;) {
      curl_socket_t fd = accept(fuzz->doh.listener, NULL, NULL);
      FUZZ_DOH_CONN *conn = NULL;
      int flags;

      if(fd < 0)
        break;
      if(fd >= FD_SETSIZE) {
        close(fd);
        continue;
      }
      for(i = 0; i < FUZZ_DOH_MAX_CONNECTIONS; i++) {
        if(fuzz->doh.conns[i].fd == CURL_SOCKET_BAD) {
          conn = &fuzz->doh.conns[i];
          break;
        }
      }
      if(!conn) {
        close(fd);
        continue;
      }

      flags = fcntl(fd, F_GETFL, 0);
      if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        continue;
      }

      conn->fd = fd;
      conn->state = FUZZ_DOH_CONN_READING;
      conn->request_len = 0;
      conn->response_len = 0;
      conn->response_off = 0;
      progress = 1;
      FV_PRINTF(fuzz, "FUZZ: DoH accepted fd %d\n", (int)fd);
    }
  }

  for(i = 0; i < FUZZ_DOH_MAX_CONNECTIONS; i++) {
    FUZZ_DOH_CONN *conn = &fuzz->doh.conns[i];
    if(conn->fd == CURL_SOCKET_BAD)
      continue;

    if(conn->state == FUZZ_DOH_CONN_READING &&
       FD_ISSET(conn->fd, readfds)) {
      for(;;) {
        ssize_t n;
        if(conn->request_len >= sizeof(conn->request))
          break;
        n = recv(conn->fd, &conn->request[conn->request_len],
                 sizeof(conn->request) - conn->request_len, 0);
        if(n > 0) {
          conn->request_len += (size_t)n;
          progress = 1;
          continue;
        }
        if(n == 0) {
          fuzz_doh_conn_close(conn);
          break;
        }
        if(errno == EINTR)
          continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        fuzz_doh_conn_close(conn);
        break;
      }

      if(conn->fd != CURL_SOCKET_BAD) {
        size_t body_off = 0;
        size_t body_len = 0;
        int complete = fuzz_doh_request_complete(conn, &body_off, &body_len);

        if(complete < 0) {
          fuzz_doh_conn_close(conn);
        }
        else if(complete > 0) {
          const unsigned char *body = &conn->request[body_off];
          unsigned char dns[512];

          if(fuzz->doh.response) {
            body = fuzz->doh.response;
            body_len = fuzz->doh.response_len;
          }
          else {
            size_t dns_len = fuzz_doh_build_dns_response(body, body_len,
                                                         dns, sizeof(dns));
            if(!dns_len) {
              fuzz_doh_conn_close(conn);
              continue;
            }
            body = dns;
            body_len = dns_len;
          }

          if(fuzz_doh_build_http_response(fuzz, conn, body, body_len) != 0)
            fuzz_doh_conn_close(conn);
          else
            conn->state = FUZZ_DOH_CONN_WRITING;
          progress = 1;
          FV_PRINTF(fuzz, "FUZZ: DoH request complete, %zu byte body\n",
                    body_len);
        }
      }
    }

    if(conn->fd != CURL_SOCKET_BAD &&
       conn->state == FUZZ_DOH_CONN_WRITING &&
       FD_ISSET(conn->fd, writefds)) {
      ssize_t n = send(conn->fd, &conn->response[conn->response_off],
                       conn->response_len - conn->response_off, 0);
      if(n > 0) {
        conn->response_off += (size_t)n;
        progress = 1;
        if(conn->response_off >= conn->response_len)
          fuzz_doh_conn_close(conn);
      }
      else if(n == 0)
        fuzz_doh_conn_close(conn);
      else if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        fuzz_doh_conn_close(conn);
    }
  }

  return progress;
}

