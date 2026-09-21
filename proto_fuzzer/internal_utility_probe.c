/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/*
 * Exercise the small container helpers that curl deliberately exports from
 * its fuzz build with UNITTESTS. They have no production call sites, but are
 * part of the private surface this project explicitly asks curl to retain.
 * Every input below is fixed and bounded, and this function runs once per
 * timing-fuzzer process.
 */

#define UNITTESTS

#include "curl_setup.h"
#include "dynhds.h"
#include "llist.h"
#include "splay.h"
#include "u32_ptrset.h"
#include "u8_strset.h"
#include "uint-bset.h"
#include "uint-spbset.h"

/* UNITTESTS makes these definitions externally visible without publishing
 * them in their normal private headers. Match curl's definitions exactly. */
bool dynhds_contains(struct dynhds *dynhds, const char *name, size_t namelen);
bool dynhds_ccontains(struct dynhds *dynhds, const char *name);
size_t dynhds_count_name(struct dynhds *dynhds, const char *name, size_t namelen);
size_t dynhds_ccount_name(struct dynhds *dynhds, const char *name);
size_t dynhds_remove(struct dynhds *dynhds, const char *name, size_t namelen);
CURLcode dynhds_set(struct dynhds *dynhds, const char *name, size_t namelen, const char *value, size_t valuelen);
size_t dynhds_cremove(struct dynhds *dynhds, const char *name);

struct Curl_llist_node *llist_tail(const struct Curl_llist *list);
struct Curl_llist_node *llist_node_prev(const struct Curl_llist_node *node);
uint32_t uint32_bset_capacity(struct uint32_bset *bset);

static bool visit_one_pointer(uint32_t id, void *ptr, void *user_data) {
  unsigned int *visits = user_data;
  (void)id;
  (void)ptr;
  ++*visits;
  return false;
}

void curl_fuzzer_probe_internal_utilities(void) {
  struct dynhds headers;
  struct Curl_llist list;
  struct Curl_llist_node first_node;
  struct Curl_llist_node second_node;
  struct uint32_bset bitset;
  struct uint32_spbset sparse_bitset;
  struct u32_ptrset pointer_set;
  struct u8_strset string_set;
  struct Curl_tree tree = {0};
  uint32_t next = 0;
  unsigned int first_value = 1;
  unsigned int second_value = 2;
  unsigned int visits = 0;

  Curl_dynhds_init(&headers, 8, 256);
  if (Curl_dynhds_cadd(&headers, "X-Probe", "one") == CURLE_OK &&
      Curl_dynhds_cadd(&headers, "X-Probe", "two") == CURLE_OK) {
    (void)dynhds_contains(&headers, "X-Probe", 7);
    (void)dynhds_ccontains(&headers, "X-Probe");
    (void)dynhds_count_name(&headers, "X-Probe", 7);
    (void)dynhds_ccount_name(&headers, "X-Probe");
    (void)dynhds_set(&headers, "X-Probe", 7, "three", 5);
    (void)dynhds_cremove(&headers, "X-Probe");
  }
  Curl_dynhds_free(&headers);

  Curl_llist_init(&list, NULL);
  Curl_llist_append(&list, &first_value, &first_node);
  Curl_llist_append(&list, &second_value, &second_node);
  (void)llist_tail(&list);
  (void)llist_node_prev(&second_node);
  Curl_llist_destroy(&list, NULL);

  Curl_uint32_bset_init(&bitset);
  if (Curl_uint32_bset_resize(&bitset, 65) == CURLE_OK) {
    (void)uint32_bset_capacity(&bitset);
    (void)Curl_uint32_bset_add(&bitset, 64);
    Curl_uint32_bset_clear(&bitset);
  }
  Curl_uint32_bset_destroy(&bitset);

  /* Moving between distant chunks reaches sparse-set allocation, ordered
   * insertion, empty-chunk reuse, and cross-chunk iteration. */
  Curl_uint32_spbset_init(&sparse_bitset);
  if (Curl_uint32_spbset_add(&sparse_bitset, 1024) && Curl_uint32_spbset_add(&sparse_bitset, 0)) {
    Curl_uint32_spbset_remove(&sparse_bitset, 1024);
    if (Curl_uint32_spbset_add(&sparse_bitset, 2048)) {
      (void)Curl_uint32_spbset_next(&sparse_bitset, 0, &next);
    }
  }
  Curl_uint32_spbset_destroy(&sparse_bitset);

  Curl_u32_ptrset_init(&pointer_set, NULL);
  if (Curl_u32_ptrset_set(&pointer_set, 7, &first_value) == CURLE_OK) {
    Curl_u32_ptrset_visit(&pointer_set, visit_one_pointer, &visits);
  }
  Curl_u32_ptrset_clear(&pointer_set);

  Curl_u8_strset_init(&string_set);
  (void)Curl_u8_strset_count(&string_set);
  Curl_u8_strset_clear(&string_set);

  tree.id = 7;
  (void)Curl_splayget(&tree);
}
