/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <stdarg.h>
#include <stddef.h>

#undef curl_multi_setopt

/* Capture callbacks at the public installation boundary. Synthetic descriptors
 * make watch exhaustion independent of network and resolver timing. */
static curl_socket_callback socket_callback;
static void *socket_userdata;
static size_t assignment_count;

int TestNotifySocket(curl_socket_t socket, int what)
{
  if(!socket_callback)
    return -2;
  return socket_callback(NULL, socket, what, socket_userdata, NULL);
}

size_t TestSocketAssignmentCount(void)
{
  return assignment_count;
}

CURLMcode curl_multi_setopt(CURLM *multi, CURLMoption option, ...)
{
  va_list args;
  (void)multi;
  va_start(args, option);
  switch(option) {
  case CURLMOPT_SOCKETFUNCTION:
    socket_callback = va_arg(args, curl_socket_callback);
    break;
  case CURLMOPT_SOCKETDATA:
    socket_userdata = va_arg(args, void *);
    break;
  default:
    break;
  }
  va_end(args);
  return CURLM_OK;
}

CURLMcode curl_multi_assign(CURLM *multi, curl_socket_t socket, void *socket_data)
{
  (void)multi;
  (void)socket;
  (void)socket_data;
  ++assignment_count;
  return CURLM_OK;
}

/* These entrypoints satisfy unexercised driver methods at link time. */
CURLMcode curl_multi_socket_action(CURLM *multi, curl_socket_t socket,
                                 int events, int *running_handles)
{
  (void)multi;
  (void)socket;
  (void)events;
  (void)running_handles;
  return CURLM_BAD_HANDLE;
}

CURLMcode curl_multi_timeout(CURLM *multi, long *timeout_ms)
{
  (void)multi;
  (void)timeout_ms;
  return CURLM_BAD_HANDLE;
}

CURLMcode curl_multi_wakeup(CURLM *multi)
{
  (void)multi;
  return CURLM_BAD_HANDLE;
}
