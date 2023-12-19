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

/**
 * TLV types.
 */
#define TLV_TYPE_MAX_CHUNKS   1
#define TLV_TYPE_CHUNK_SIZE   2
#define TLV_TYPE_USE_POOL   3
#define TLV_TYPE_READ_SIZE   4
#define TLV_TYPE_WRITE_SIZE   5
#define TLV_TYPE_SKIP_SIZE   6
#define TLV_TYPE_MAX_SPARE 7
#define TLV_TYPE_NO_SPARE 8

#define TLV_MAX_CHUNK_SIZE (16 * 1024)
#define TLV_MAX_CHUNKS_QTY (1 * 1024)
#define TLV_MAX_MAX_SPARE (1 * 1024)

typedef struct fuzz_data_bufq FUZZ_DATA;

#define OP_TYPE_WRITE 0
#define OP_TYPE_READ 1
#define OP_TYPE_SKIP 2

typedef struct fuzz_bufq_operation {
  unsigned int type;
  unsigned int size;
  struct fuzz_bufq_operation *next;
} OPERATION;