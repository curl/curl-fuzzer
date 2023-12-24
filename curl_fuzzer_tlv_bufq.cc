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
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * Do different actions on the CURL handle for different received TLVs.
 */
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv)
{
  int rc;
  OPERATION *tmp_op;
  uint32_t tmp_op_type;
  uint32_t tmp_u32;

  switch(tlv->type) {
    case TLV_TYPE_MAX_CHUNKS:
      FCHECK(fuzz->max_chunks == 0);
      if(tlv->length != 4) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp_u32 = to_u32(tlv->value);
      FCHECK(tmp_u32 > 0 && tmp_u32 < TLV_MAX_CHUNKS_QTY);
      fuzz->max_chunks = tmp_u32;
      break;
    
    case TLV_TYPE_CHUNK_SIZE:
      FCHECK(fuzz->chunk_size == 0);
      if(tlv->length != 4) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp_u32 = to_u32(tlv->value);
      FCHECK(tmp_u32 > 0 && tmp_u32 < TLV_MAX_CHUNK_SIZE);
      fuzz->chunk_size = tmp_u32;
      break;

    case TLV_TYPE_MAX_SPARE:
      FCHECK(fuzz->max_spare == 0);
      if(tlv->length != 4) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp_u32 = to_u32(tlv->value);
      FCHECK(tmp_u32 > 0 && tmp_u32 < TLV_MAX_MAX_SPARE);
      fuzz->max_spare = tmp_u32;
      break;

    case TLV_TYPE_USE_POOL:
      FCHECK(fuzz->use_pool == 0);
      fuzz->use_pool = 1;
      break;

    case TLV_TYPE_NO_SPARE:
      FCHECK(fuzz->no_spare == 0);
      fuzz->no_spare = 1;
      break;

    case TLV_TYPE_READ_SIZE:
      tmp_op_type = OP_TYPE_READ;
      goto ADD_OP;

    case TLV_TYPE_SKIP_SIZE:
      tmp_op_type = OP_TYPE_SKIP;
      goto ADD_OP;

    case TLV_TYPE_WRITE_SIZE:
      tmp_op_type = OP_TYPE_WRITE;
ADD_OP:
      if(tlv->length != 4) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp_u32 = to_u32(tlv->value);
      FCHECK(tmp_u32 <= TLV_MAX_RW_SIZE);
      tmp_op = (OPERATION*) malloc(sizeof(*tmp_op));
      if (tmp_op == NULL) {
        // keep on despite allocation failure
        break;
      }
      tmp_op->type = tmp_op_type;
      tmp_op->size = tmp_u32;
      tmp_op->next = fuzz->operation_list;
      fuzz->operation_list = tmp_op;
      fuzz->operation_count++;
      break;

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      FV_PRINTF(fuzz, "Unknown TLV!\n");
      rc = 127;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:
  return rc;
}
