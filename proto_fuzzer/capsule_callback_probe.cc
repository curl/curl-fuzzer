/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/*
 * A failed inner QUIC handshake naturally exercises capsule connect, I/O,
 * control, query, and destruction through the HTTP/3 easy path. The three
 * callbacks below require either a completed origin handshake or retained
 * buffered state. Check their empty-state contracts once without creating a
 * separate fuzzer or accepting mutation-controlled internal layouts.
 */

#include <curl/curl.h>

#include <cstdlib>

extern "C" {
// curl_setup.h must precede its dependent private headers.
// clang-format off
#include "curl_setup.h"
#include "urldata.h"
#include "cfilters.h"
#include "select.h"
#include "vquic/cf-capsule.h"
// clang-format on
}

namespace {

void DestroyAnchor(Curl_cfilter*, Curl_easy*) {}

const Curl_cftype kAnchorFilter = {
    "CAPSULE-PROBE-ANCHOR",
    CF_TYPE_SETUP,
    0,
    DestroyAnchor,
    Curl_cf_def_connect,
    Curl_cf_def_shutdown,
    Curl_cf_def_adjust_pollset,
    Curl_cf_def_data_pending,
    Curl_cf_def_send,
    Curl_cf_def_recv,
    Curl_cf_def_cntrl,
    Curl_cf_def_conn_is_alive,
    Curl_cf_def_conn_keep_alive,
    Curl_cf_def_query,
};

void Require(bool condition) {
  if (!condition) {
    std::abort();
  }
}

}  // namespace

extern "C" void curl_fuzzer_probe_capsule_callbacks(void) {
  CURL* public_easy = curl_easy_init();
  Require(public_easy != nullptr);
  auto* easy = reinterpret_cast<Curl_easy*>(public_easy);
  connectdata connection{};
  Curl_cfilter* anchor = nullptr;
  Require(Curl_cf_create(&anchor, &kAnchorFilter, nullptr) == CURLE_OK);
  Curl_conn_cf_add(easy, &connection, FIRSTSOCKET, anchor);
  Require(Curl_cf_capsule_insert_after(anchor, easy) == CURLE_OK);

  Curl_cfilter* capsule = anchor->next;
  Require(capsule != nullptr);
  bool done = false;
  easy_pollset pollset{};
  Require(capsule->cft->do_shutdown(capsule, easy, &done) == CURLE_OK && done);
  Require(capsule->cft->adjust_pollset(capsule, easy, &pollset) == CURLE_OK);
  Require(!capsule->cft->has_data_pending(capsule, easy));

  Curl_conn_cf_discard_chain(&connection.cfilter[FIRSTSOCKET], easy);
  curl_easy_cleanup(public_easy);
}
