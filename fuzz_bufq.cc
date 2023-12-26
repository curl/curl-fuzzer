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
#include <sys/mman.h>
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
 * Allocate template buffer.  This buffer is precomputed for performance and
 * used as a cyclic pattern when reading and writing. It can be useful to
 * detect unexpected data shifting or corruption. The buffer is marked
 * read-only so it cannot be written by mistake.
 */
static unsigned char *allocate_template_buffer(void)
{
  size_t sz = TLV_MAX_RW_SIZE + 256;
  unsigned char *buf = (unsigned char *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  assert(buf != (unsigned char *)-1);

  /* Fill in with a cyclic pattern of 0, 1, ..., 255, 0, ... */
  unsigned char next_byte = 0;
  for (size_t i = 0; i < sz; i++) {
    buf[i] = next_byte++;
  }

  int err = mprotect(buf, sz, PROT_READ);
  assert(err == 0);
  return buf;
}

/*
 * Compute a pointer to a read-only buffer with our pattern, knowing that the
 * first byte to appear is next_byte.
 */
static unsigned char *compute_buffer(unsigned char next_byte, unsigned char *buf) {
  return buf + next_byte;
}

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the cURL API into making a series of
 * BUFQ operations.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  static unsigned char *template_buf = allocate_template_buffer();
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

  /* Add our template buffer */
  fuzz.template_buf = template_buf;

  /* Run the operations */
  fuzz_handle_bufq(&fuzz);

EXIT_LABEL:

  fuzz_terminate_fuzz_data(&fuzz);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
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

struct writer_cb_ctx {
  FUZZ_DATA *fuzz;
  ssize_t read_len;
  unsigned char next_byte_read;
};

ssize_t bufq_writer_cb(void *writer_ctx,
                         const unsigned char *buf, size_t len,
                         CURLcode *err)
{
  struct writer_cb_ctx *ctx = (struct writer_cb_ctx *)writer_ctx;

  if (ctx->read_len <= 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  FV_PRINTF(ctx->fuzz, "Writer CB: %zu space available, %zu pending\n", len, ctx->read_len);

  size_t sz = len > ctx->read_len ? ctx->read_len : len;

  unsigned char *compare = compute_buffer(ctx->next_byte_read, ctx->fuzz->template_buf);
  assert(memcmp(buf, compare, sz) == 0);
  ctx->next_byte_read += sz;
  ctx->read_len -= sz;

  return sz;
}


struct reader_cb_ctx {
  FUZZ_DATA *fuzz;
  ssize_t write_len;
  unsigned char next_byte_write;
};

static ssize_t bufq_reader_cb(void *reader_ctx,
                              unsigned char *buf, size_t len,
                              CURLcode *err)
{
  struct reader_cb_ctx *ctx = (struct reader_cb_ctx *)reader_ctx;

  if (ctx->write_len <= 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  FV_PRINTF(ctx->fuzz, "Reader CB: %zu space available, %zu pending\n", len, ctx->write_len);

  size_t sz = len > ctx->write_len ? ctx->write_len : len;

  unsigned char *compare = compute_buffer(ctx->next_byte_write, ctx->fuzz->template_buf);
  memcpy(buf, compare, sz);
  ctx->next_byte_write += sz;
  ctx->write_len -= sz;

  return sz;
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

    assert(Curl_bufq_is_empty(&q) == !buffer_bytes);
    assert(Curl_bufq_len(&q) == buffer_bytes);
  
    switch (op->type) {
      case OP_TYPE_RESET: {
        FV_PRINTF(fuzz, "OP: reset\n");
        Curl_bufq_reset(&q);
        buffer_bytes = 0;
        next_byte_read = next_byte_write;
        break;
      }

      case OP_TYPE_PEEK: {
        FV_PRINTF(fuzz, "OP: peek\n");
        const unsigned char *pbuf;
        size_t plen;
        bool avail = Curl_bufq_peek(&q, &pbuf, &plen);
        if (avail) {
          unsigned char *compare = compute_buffer(next_byte_read, fuzz->template_buf);
          assert(memcmp(pbuf, compare, plen) == 0);
        } else {
          FV_PRINTF(fuzz, "OP: peek, error\n");
        }
        break;
      }

      case OP_TYPE_PEEK_AT: {
        FV_PRINTF(fuzz, "OP: peek at %u\n", op->size);
        const unsigned char *pbuf;
        size_t plen;
        bool avail = Curl_bufq_peek_at(&q, op->size, &pbuf, &plen);
        if (avail) {
          unsigned char *compare = compute_buffer(next_byte_read + op->size, fuzz->template_buf);
          assert(memcmp(pbuf, compare, plen) == 0);
        } else {
          FV_PRINTF(fuzz, "OP: peek at, error\n");
        }
        break;
      }

      case OP_TYPE_READ: {
        FV_PRINTF(fuzz, "OP: read, size %u\n", op->size);
        unsigned char *buf = (unsigned char *)malloc(op->size * sizeof(*buf));
        ssize_t read = Curl_bufq_read(&q, buf, op->size, &err);
        if (read != -1) {
          FV_PRINTF(fuzz, "OP: read, success, read %zd, expect begins with %x\n", read, next_byte_read);
          buffer_bytes -= read;
          assert(buffer_bytes >= 0);
          unsigned char *compare = compute_buffer(next_byte_read, fuzz->template_buf);
          next_byte_read += read;
          assert(memcmp(buf, compare, read) == 0);
        } else {
          FV_PRINTF(fuzz, "OP: read, error\n");
        }
        free(buf);
        break;
      }

      case OP_TYPE_SLURP: {
        FV_PRINTF(fuzz, "OP: slurp, size %u\n", op->size);
        struct reader_cb_ctx ctx = { .fuzz = fuzz, .write_len = op->size, .next_byte_write = next_byte_write };
        ssize_t write = Curl_bufq_slurp(&q, bufq_reader_cb, &ctx, &err);
        if (write != -1) {
          FV_PRINTF(fuzz, "OP: slurp, success, wrote %zd, expect begins with %x\n", write, ctx.next_byte_write);
          buffer_bytes += write;
        } else {
          FV_PRINTF(fuzz, "OP: slurp, error\n");
          /* in case of -1, it may still have wrote something, adjust for that */
          buffer_bytes += (op->size - ctx.write_len);
        }
        assert(buffer_bytes <= fuzz->chunk_size * fuzz->max_chunks);
        next_byte_write = ctx.next_byte_write;
        break;
      }

      case OP_TYPE_SIPN: {
        FV_PRINTF(fuzz, "OP: sipn, size %u\n", op->size);
        struct reader_cb_ctx ctx = { .fuzz = fuzz, .write_len = op->size, .next_byte_write = next_byte_write };
        ssize_t write = Curl_bufq_sipn(&q, op->size, bufq_reader_cb, &ctx, &err);
        if (write != -1) {
          FV_PRINTF(fuzz, "OP: sipn, success, wrote %zd, expect begins with %x\n", write, ctx.next_byte_write);
          buffer_bytes += write;
          assert(buffer_bytes <= fuzz->chunk_size * fuzz->max_chunks);
          next_byte_write = ctx.next_byte_write;
        } else {
          FV_PRINTF(fuzz, "OP: sipn, error\n");
        }
        break;
      }

      case OP_TYPE_PASS: {
        FV_PRINTF(fuzz, "OP: pass, size %u\n", op->size);
        struct writer_cb_ctx ctx = { .fuzz = fuzz, .read_len = op->size, .next_byte_read = next_byte_read };
        ssize_t read = Curl_bufq_pass(&q, bufq_writer_cb, &ctx, &err);
        if (read != -1) {
          FV_PRINTF(fuzz, "OP: pass, success, read %zd, expect begins with %x\n", read, ctx.next_byte_read);
          buffer_bytes -= read;
        } else {
          FV_PRINTF(fuzz, "OP: pass, error\n");
          /* in case of -1, it may still have read something, adjust for that */
          buffer_bytes -= (op->size - ctx.read_len);
        }
        assert(buffer_bytes >= 0);
        next_byte_read = ctx.next_byte_read;
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
        unsigned char *buf = compute_buffer(next_byte_write, fuzz->template_buf);
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
  }

  Curl_bufq_free(&q);
  if (fuzz->use_pool)
  {
    Curl_bufcp_free(&pool);
  }
  
  return 0;
}