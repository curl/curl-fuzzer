/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 - 2022, Max Dymond, <cmeister2@gmail.com>, et al.
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

#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
extern "C" {
#include "bufq.h"
}

#ifndef TLV_ENUM_BUFQ
#error "Do not forget to define TLV_ENUM_BUFQ to build this harness"
#endif
#include "curl_fuzzer.h"

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the cURL API into making a series of
 * BUFQ operations.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz;
  TLV tlv;

  /* Ignore SIGPIPE errors. We'll handle the errors ourselves. */
  signal(SIGPIPE, SIG_IGN);

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
    FV_PRINTF(&fuzz, "FUZZ: TLV failed, can't continue\n");
    goto EXIT_LABEL;
  }

  /* Check that all required TLVs were present */
  FCHECK(fuzz.max_chunks > 0);
  FCHECK(fuzz.chunk_size > 0);
  FCHECK(!fuzz.use_pool || fuzz.max_spare > 0);

  /* Run the operations */
  fuzz_handle_bufq(&fuzz);

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
  int ii;

  /* Initialize the fuzz data. */
  memset(fuzz, 0, sizeof(FUZZ_DATA));

  /* Set up the state parser */
  fuzz->state.data = data;
  fuzz->state.data_len = data_len;

  /* Check for verbose mode. */
  fuzz->verbose = (getenv("FUZZ_VERBOSE") != NULL);

  return rc;
}


/**
 * Terminate the fuzz data structure, including freeing any allocated memory.
 */
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz)
{
  while(fuzz->operation_list != NULL) {
    OPERATION *tmp = fuzz->operation_list->next;
    free(fuzz->operation_list);
    fuzz->operation_list = tmp;
  }
}

/**
 * If a pointer has been allocated, free that pointer.
 */
void fuzz_free(void **ptr)
{
  free(*ptr);
  *ptr = NULL;
}

unsigned char fill_buffer(unsigned char next_byte, unsigned char *buf, size_t length) {
  size_t i;
  for (i = 0; i+3 < length; i+=4, next_byte+=4) {
    buf[i] = next_byte;
    buf[i+1] = next_byte + 1;
    buf[i+2] = next_byte + 2;
    buf[i+3] = next_byte + 3;
  }
  for (; i < length; i++) {
    buf[i] = next_byte++;
  }
  return next_byte;
}

/**
 * Function for handling the operations
 */
int fuzz_handle_bufq(FUZZ_DATA *fuzz)
{
  struct bufq q;
  struct bufc_pool pool;

  FV_PRINTF(fuzz, "Begin fuzzing!\n");

  if (fuzz->use_pool == 0)
  {
    FV_PRINTF(fuzz, "Using normal init\n");
    Curl_bufq_init(&q, fuzz->chunk_size, fuzz->max_chunks);
  } else {
    FV_PRINTF(fuzz, "Using pool init\n");
    Curl_bufcp_init(&pool, fuzz->chunk_size, fuzz->max_spare);
    Curl_bufq_initp(&q, &pool, fuzz->max_chunks, fuzz->no_spare ? BUFQ_OPT_NO_SPARES : BUFQ_OPT_NONE);
  }

  ssize_t buffer_bytes = 0;
  unsigned char next_byte_read = 0;
  unsigned char next_byte_write = 0;
  for(OPERATION *op = fuzz->operation_list; op != NULL; op = op->next) {
    CURLcode err = CURLE_OK;
    unsigned char *buf = (unsigned char *)malloc(op->size * sizeof(*buf));
  
    switch (op->type) {
      case OP_TYPE_READ: {
        FV_PRINTF(fuzz, "OP: read, size %u\n", op->size);
        ssize_t read = Curl_bufq_read(&q, buf, op->size, &err);
        if (read != -1) {
          FV_PRINTF(fuzz, "OP: read, success, read %zd, expect begins with %x\n", read, next_byte_read);
          buffer_bytes -= read;
          assert(buffer_bytes >= 0);
          unsigned char *compare = (unsigned char *)malloc(read * sizeof(*buf));
          next_byte_read = fill_buffer(next_byte_read, compare, read);
          assert(memcmp(buf, compare, read) == 0);
          free(compare);
        } else {
          FV_PRINTF(fuzz, "OP: read, error\n");
        }
        break;
      }

      case OP_TYPE_SKIP: {
        FV_PRINTF(fuzz, "OP: skip, size %u\n", op->size);
        Curl_bufq_skip(&q, op->size);
        ssize_t old_buffer_bytes = buffer_bytes;
        buffer_bytes = old_buffer_bytes > op->size ? old_buffer_bytes - op->size : 0;
        next_byte_read += old_buffer_bytes > op->size ? op->size : old_buffer_bytes;
        break;
      }

      case OP_TYPE_WRITE:
      default: {
        FV_PRINTF(fuzz, "OP: write, size %u, begins with %x\n", op->size, next_byte_write);
        fill_buffer(next_byte_write, buf, op->size);
        ssize_t written = Curl_bufq_write(&q, buf, op->size, &err);
        if (written != -1) {
          FV_PRINTF(fuzz, "OP: write, success, written %zd\n", written);
          next_byte_write += written;
          buffer_bytes += written;
          assert(buffer_bytes <= fuzz->chunk_size * fuzz->max_chunks);
        } else {
          FV_PRINTF(fuzz, "OP: write, error\n");
        }
        break;
      }
    }

    free(buf);
  }

  Curl_bufq_free(&q);
  if (fuzz->use_pool)
  {
    Curl_bufcp_free(&pool);
  }
  
  return 0;
}