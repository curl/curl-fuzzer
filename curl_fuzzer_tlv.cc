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

  FV_PRINTF(fuzz, "TLV: type %x length %u\n", tlv->type, tlv->length);

  /* Use uint64s to verify lengths of TLVs so that overflow problems don't
     matter. */
  uint64_t check_length = data_offset;
  check_length += tlv->length;

  uint64_t remaining_len = fuzz->state.data_len;
  FV_PRINTF(fuzz, "Check length of data: %" PRIu64 " \n", check_length);
  FV_PRINTF(fuzz, "Remaining length of data: %" PRIu64 " \n", remaining_len);

  /* Sanity check that the TLV length is ok. */
  if(check_length > remaining_len) {
    FV_PRINTF(fuzz, "Returning TLV_RC_SIZE_ERROR\n");
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
  char *tmp = NULL;
  uint32_t tmp_u32;
  curl_slist *new_list;

  switch(tlv->type) {
    /* The pointers in response TLVs will always be valid as long as the fuzz
       data is in scope, which is the entirety of this file. */
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE0, 0);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE1, 1);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE2, 2);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE3, 3);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE4, 4);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE5, 5);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE6, 6);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE7, 7);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE8, 8);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE9, 9);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE10, 10);

    FRESPONSETLV(&fuzz->sockman[1], TLV_TYPE_SECOND_RESPONSE0, 0);
    FRESPONSETLV(&fuzz->sockman[1], TLV_TYPE_SECOND_RESPONSE1, 1);

    case TLV_TYPE_UPLOAD1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */

      FCHECK_OPTION_UNSET(fuzz, CURLOPT_UPLOAD);

      fuzz->upload1_data = tlv->value;
      fuzz->upload1_data_len = tlv->length;

      FSET_OPTION(fuzz, CURLOPT_UPLOAD, 1L);
      FSET_OPTION(fuzz,
                  CURLOPT_INFILESIZE_LARGE,
                  (curl_off_t)fuzz->upload1_data_len);
      break;

    case TLV_TYPE_HEADER:
      /* Limit the number of headers that can be added to a message to prevent
         timeouts. */
      if(fuzz->header_list_count >= TLV_MAX_NUM_CURLOPT_HEADER) {
        rc = 255;
        goto EXIT_LABEL;
      }

      tmp = fuzz_tlv_to_string(tlv);
      if (tmp == NULL) {
        // keep on despite allocation failure
        break;
      }
      new_list = curl_slist_append(fuzz->header_list, tmp);
      if (new_list == NULL) {
        break;
      }
      fuzz->header_list = new_list;
      fuzz->header_list_count++;
      break;

    case TLV_TYPE_MAIL_RECIPIENT:
      /* Limit the number of headers that can be added to a message to prevent
         timeouts. */
      if(fuzz->header_list_count >= TLV_MAX_NUM_CURLOPT_HEADER) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp = fuzz_tlv_to_string(tlv);
      if (tmp == NULL) {
        // keep on despite allocation failure
        break;
      }
      new_list = curl_slist_append(fuzz->mail_recipients_list, tmp);
      if (new_list != NULL) {
        fuzz->mail_recipients_list = new_list;
        fuzz->header_list_count++;
      }
      break;

    case TLV_TYPE_MIME_PART:
      if(fuzz->mime == NULL) {
        fuzz->mime = curl_mime_init(fuzz->easy);
      }

      fuzz->part = curl_mime_addpart(fuzz->mime);

      /* This TLV may have sub TLVs. */
      fuzz_add_mime_part(tlv, fuzz->part);

      break;

    case TLV_TYPE_POSTFIELDS:
      FCHECK_OPTION_UNSET(fuzz, CURLOPT_POSTFIELDS);
      fuzz->postfields = fuzz_tlv_to_string(tlv);
      FSET_OPTION(fuzz, CURLOPT_POSTFIELDS, fuzz->postfields);
      break;

    case TLV_TYPE_HTTPPOSTBODY:
      FCHECK_OPTION_UNSET(fuzz, CURLOPT_HTTPPOST);
      fuzz_setup_http_post(fuzz, tlv);
      FSET_OPTION(fuzz, CURLOPT_HTTPPOST, fuzz->httppost);
      break;

    /* Define a set of u32 options. */
    FU32TLV(fuzz, TLV_TYPE_HTTPAUTH, CURLOPT_HTTPAUTH);
    FU32TLV(fuzz, TLV_TYPE_OPTHEADER, CURLOPT_HEADER);
    FU32TLV(fuzz, TLV_TYPE_NOBODY, CURLOPT_NOBODY);
    FU32TLV(fuzz, TLV_TYPE_FOLLOWLOCATION, CURLOPT_FOLLOWLOCATION);
    FU32TLV(fuzz, TLV_TYPE_WILDCARDMATCH, CURLOPT_WILDCARDMATCH);
    FU32TLV(fuzz, TLV_TYPE_RTSP_REQUEST, CURLOPT_RTSP_REQUEST);
    FU32TLV(fuzz, TLV_TYPE_RTSP_CLIENT_CSEQ, CURLOPT_RTSP_CLIENT_CSEQ);
    FU32TLV(fuzz, TLV_TYPE_HTTP_VERSION, CURLOPT_HTTP_VERSION);
    FU32TLV(fuzz, TLV_TYPE_NETRC, CURLOPT_NETRC);
    FU32TLV(fuzz, TLV_TYPE_WS_OPTIONS, CURLOPT_WS_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_CONNECT_ONLY, CURLOPT_CONNECT_ONLY);
    FU32TLV(fuzz, TLV_TYPE_POST, CURLOPT_POST);
    FU32TLV(fuzz, TLV_TYPE_PROXYTYPE, CURLOPT_PROXYTYPE);
    FU32TLV(fuzz, TLV_TYPE_PORT, CURLOPT_PORT);
    FU32TLV(fuzz, TLV_TYPE_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_LIMIT);
    FU32TLV(fuzz, TLV_TYPE_LOW_SPEED_TIME, CURLOPT_LOW_SPEED_TIME);
    FU32TLV(fuzz, TLV_TYPE_RESUME_FROM, CURLOPT_RESUME_FROM);
    FU32TLV(fuzz, TLV_TYPE_TIMEVALUE, CURLOPT_TIMEVALUE);
    FU32TLV(fuzz, TLV_TYPE_NOPROGRESS, CURLOPT_NOPROGRESS);
    FU32TLV(fuzz, TLV_TYPE_FAILONERROR, CURLOPT_FAILONERROR);
    FU32TLV(fuzz, TLV_TYPE_DIRLISTONLY, CURLOPT_DIRLISTONLY);
    FU32TLV(fuzz, TLV_TYPE_APPEND, CURLOPT_APPEND);
    FU32TLV(fuzz, TLV_TYPE_TRANSFERTEXT, CURLOPT_TRANSFERTEXT);
    FU32TLV(fuzz, TLV_TYPE_AUTOREFERER, CURLOPT_AUTOREFERER);
    FU32TLV(fuzz, TLV_TYPE_PROXYPORT, CURLOPT_PROXYPORT);
    // too easy for API misuse FU32TLV(fuzz, TLV_TYPE_POSTFIELDSIZE, CURLOPT_POSTFIELDSIZE);
    FU32TLV(fuzz, TLV_TYPE_HTTPPROXYTUNNEL, CURLOPT_HTTPPROXYTUNNEL);
    FU32TLV(fuzz, TLV_TYPE_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYPEER);
    FU32TLV(fuzz, TLV_TYPE_MAXREDIRS, CURLOPT_MAXREDIRS);
    FU32TLV(fuzz, TLV_TYPE_FILETIME, CURLOPT_FILETIME);
    FU32TLV(fuzz, TLV_TYPE_MAXCONNECTS, CURLOPT_MAXCONNECTS);
    FU32TLV(fuzz, TLV_TYPE_FRESH_CONNECT, CURLOPT_FRESH_CONNECT);
    FU32TLV(fuzz, TLV_TYPE_FORBID_REUSE, CURLOPT_FORBID_REUSE);
    FU32TLV(fuzz, TLV_TYPE_CONNECTTIMEOUT, CURLOPT_CONNECTTIMEOUT);
    FU32TLV(fuzz, TLV_TYPE_HTTPGET, CURLOPT_HTTPGET);
    FU32TLV(fuzz, TLV_TYPE_SSL_VERIFYHOST, CURLOPT_SSL_VERIFYHOST);
    FU32TLV(fuzz, TLV_TYPE_FTP_USE_EPSV, CURLOPT_FTP_USE_EPSV);
    FU32TLV(fuzz, TLV_TYPE_SSLENGINE_DEFAULT, CURLOPT_SSLENGINE_DEFAULT);
    FU32TLV(fuzz, TLV_TYPE_DNS_CACHE_TIMEOUT, CURLOPT_DNS_CACHE_TIMEOUT);
    FU32TLV(fuzz, TLV_TYPE_COOKIESESSION, CURLOPT_COOKIESESSION);
    FU32TLV(fuzz, TLV_TYPE_BUFFERSIZE, CURLOPT_BUFFERSIZE);
    FU32TLV(fuzz, TLV_TYPE_NOSIGNAL, CURLOPT_NOSIGNAL);
    FU32TLV(fuzz, TLV_TYPE_UNRESTRICTED_AUTH, CURLOPT_UNRESTRICTED_AUTH);
    FU32TLV(fuzz, TLV_TYPE_FTP_USE_EPRT, CURLOPT_FTP_USE_EPRT);
    FU32TLV(fuzz, TLV_TYPE_FTP_CREATE_MISSING_DIRS, CURLOPT_FTP_CREATE_MISSING_DIRS);
    FU32TLV(fuzz, TLV_TYPE_MAXFILESIZE, CURLOPT_MAXFILESIZE);
    FU32TLV(fuzz, TLV_TYPE_TCP_NODELAY, CURLOPT_TCP_NODELAY);
    FU32TLV(fuzz, TLV_TYPE_IGNORE_CONTENT_LENGTH, CURLOPT_IGNORE_CONTENT_LENGTH);
    FU32TLV(fuzz, TLV_TYPE_FTP_SKIP_PASV_IP, CURLOPT_FTP_SKIP_PASV_IP);
    FU32TLV(fuzz, TLV_TYPE_LOCALPORT, CURLOPT_LOCALPORT);
    FU32TLV(fuzz, TLV_TYPE_LOCALPORTRANGE, CURLOPT_LOCALPORTRANGE);
    FU32TLV(fuzz, TLV_TYPE_SSL_SESSIONID_CACHE, CURLOPT_SSL_SESSIONID_CACHE);
    FU32TLV(fuzz, TLV_TYPE_FTP_SSL_CCC, CURLOPT_FTP_SSL_CCC);
    FU32TLV(fuzz, TLV_TYPE_CONNECTTIMEOUT_MS, CURLOPT_CONNECTTIMEOUT_MS);
    FU32TLV(fuzz, TLV_TYPE_HTTP_TRANSFER_DECODING, CURLOPT_HTTP_TRANSFER_DECODING);
    FU32TLV(fuzz, TLV_TYPE_HTTP_CONTENT_DECODING, CURLOPT_HTTP_CONTENT_DECODING);
    FU32TLV(fuzz, TLV_TYPE_NEW_FILE_PERMS, CURLOPT_NEW_FILE_PERMS);
    FU32TLV(fuzz, TLV_TYPE_NEW_DIRECTORY_PERMS, CURLOPT_NEW_DIRECTORY_PERMS);
    FU32TLV(fuzz, TLV_TYPE_PROXY_TRANSFER_MODE, CURLOPT_PROXY_TRANSFER_MODE);
    FU32TLV(fuzz, TLV_TYPE_ADDRESS_SCOPE, CURLOPT_ADDRESS_SCOPE);
    FU32TLV(fuzz, TLV_TYPE_CERTINFO, CURLOPT_CERTINFO);
    FU32TLV(fuzz, TLV_TYPE_TFTP_BLKSIZE, CURLOPT_TFTP_BLKSIZE);
    FU32TLV(fuzz, TLV_TYPE_SOCKS5_GSSAPI_NEC, CURLOPT_SOCKS5_GSSAPI_NEC);
    FU32TLV(fuzz, TLV_TYPE_FTP_USE_PRET, CURLOPT_FTP_USE_PRET);
    FU32TLV(fuzz, TLV_TYPE_RTSP_SERVER_CSEQ, CURLOPT_RTSP_SERVER_CSEQ);
    FU32TLV(fuzz, TLV_TYPE_TRANSFER_ENCODING, CURLOPT_TRANSFER_ENCODING);
    FU32TLV(fuzz, TLV_TYPE_ACCEPTTIMEOUT_MS, CURLOPT_ACCEPTTIMEOUT_MS);
    FU32TLV(fuzz, TLV_TYPE_TCP_KEEPALIVE, CURLOPT_TCP_KEEPALIVE);
    FU32TLV(fuzz, TLV_TYPE_TCP_KEEPIDLE, CURLOPT_TCP_KEEPIDLE);
    FU32TLV(fuzz, TLV_TYPE_TCP_KEEPINTVL, CURLOPT_TCP_KEEPINTVL);
    FU32TLV(fuzz, TLV_TYPE_SASL_IR, CURLOPT_SASL_IR);
    FU32TLV(fuzz, TLV_TYPE_SSL_ENABLE_ALPN, CURLOPT_SSL_ENABLE_ALPN);
    FU32TLV(fuzz, TLV_TYPE_EXPECT_100_TIMEOUT_MS, CURLOPT_EXPECT_100_TIMEOUT_MS);
    FU32TLV(fuzz, TLV_TYPE_SSL_VERIFYSTATUS, CURLOPT_SSL_VERIFYSTATUS);
    FU32TLV(fuzz, TLV_TYPE_SSL_FALSESTART, CURLOPT_SSL_FALSESTART);
    FU32TLV(fuzz, TLV_TYPE_PATH_AS_IS, CURLOPT_PATH_AS_IS);
    FU32TLV(fuzz, TLV_TYPE_PIPEWAIT, CURLOPT_PIPEWAIT);
    FU32TLV(fuzz, TLV_TYPE_STREAM_WEIGHT, CURLOPT_STREAM_WEIGHT);
    FU32TLV(fuzz, TLV_TYPE_TFTP_NO_OPTIONS, CURLOPT_TFTP_NO_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_TCP_FASTOPEN, CURLOPT_TCP_FASTOPEN);
    FU32TLV(fuzz, TLV_TYPE_KEEP_SENDING_ON_ERROR, CURLOPT_KEEP_SENDING_ON_ERROR);
    FU32TLV(fuzz, TLV_TYPE_PROXY_SSL_VERIFYPEER, CURLOPT_PROXY_SSL_VERIFYPEER);
    FU32TLV(fuzz, TLV_TYPE_PROXY_SSL_VERIFYHOST, CURLOPT_PROXY_SSL_VERIFYHOST);
    FU32TLV(fuzz, TLV_TYPE_PROXY_SSL_OPTIONS, CURLOPT_PROXY_SSL_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_SUPPRESS_CONNECT_HEADERS, CURLOPT_SUPPRESS_CONNECT_HEADERS);
    FU32TLV(fuzz, TLV_TYPE_SOCKS5_AUTH, CURLOPT_SOCKS5_AUTH);
    FU32TLV(fuzz, TLV_TYPE_SSH_COMPRESSION, CURLOPT_SSH_COMPRESSION);
    FU32TLV(fuzz, TLV_TYPE_HAPPY_EYEBALLS_TIMEOUT_MS, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS);
    FU32TLV(fuzz, TLV_TYPE_HAPROXYPROTOCOL, CURLOPT_HAPROXYPROTOCOL);
    FU32TLV(fuzz, TLV_TYPE_DNS_SHUFFLE_ADDRESSES, CURLOPT_DNS_SHUFFLE_ADDRESSES);
    FU32TLV(fuzz, TLV_TYPE_DISALLOW_USERNAME_IN_URL, CURLOPT_DISALLOW_USERNAME_IN_URL);
    FU32TLV(fuzz, TLV_TYPE_UPLOAD_BUFFERSIZE, CURLOPT_UPLOAD_BUFFERSIZE);
    FU32TLV(fuzz, TLV_TYPE_UPKEEP_INTERVAL_MS, CURLOPT_UPKEEP_INTERVAL_MS);
    FU32TLV(fuzz, TLV_TYPE_HTTP09_ALLOWED, CURLOPT_HTTP09_ALLOWED);
    FU32TLV(fuzz, TLV_TYPE_ALTSVC_CTRL, CURLOPT_ALTSVC_CTRL);
    FU32TLV(fuzz, TLV_TYPE_MAXAGE_CONN, CURLOPT_MAXAGE_CONN);
    FU32TLV(fuzz, TLV_TYPE_MAIL_RCPT_ALLOWFAILS, CURLOPT_MAIL_RCPT_ALLOWFAILS);
    FU32TLV(fuzz, TLV_TYPE_HSTS_CTRL, CURLOPT_HSTS_CTRL);
    FU32TLV(fuzz, TLV_TYPE_DOH_SSL_VERIFYPEER, CURLOPT_DOH_SSL_VERIFYPEER);
    FU32TLV(fuzz, TLV_TYPE_DOH_SSL_VERIFYHOST, CURLOPT_DOH_SSL_VERIFYHOST);
    FU32TLV(fuzz, TLV_TYPE_DOH_SSL_VERIFYSTATUS, CURLOPT_DOH_SSL_VERIFYSTATUS);
    FU32TLV(fuzz, TLV_TYPE_MAXLIFETIME_CONN, CURLOPT_MAXLIFETIME_CONN);
    FU32TLV(fuzz, TLV_TYPE_MIME_OPTIONS, CURLOPT_MIME_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_CA_CACHE_TIMEOUT, CURLOPT_CA_CACHE_TIMEOUT);
    FU32TLV(fuzz, TLV_TYPE_QUICK_EXIT, CURLOPT_QUICK_EXIT);
    FU32TLV(fuzz, TLV_TYPE_SERVER_RESPONSE_TIMEOUT_MS, CURLOPT_SERVER_RESPONSE_TIMEOUT_MS);
    FU32TLV(fuzz, TLV_TYPE_TCP_KEEPCNT, CURLOPT_TCP_KEEPCNT);
    FU32TLV(fuzz, TLV_TYPE_SSLVERSION, CURLOPT_SSLVERSION);
    FU32TLV(fuzz, TLV_TYPE_TIMECONDITION, CURLOPT_TIMECONDITION);
    FU32TLV(fuzz, TLV_TYPE_PROXYAUTH, CURLOPT_PROXYAUTH);
    FU32TLV(fuzz, TLV_TYPE_IPRESOLVE, CURLOPT_IPRESOLVE);
    FU32TLV(fuzz, TLV_TYPE_USE_SSL, CURLOPT_USE_SSL);
    FU32TLV(fuzz, TLV_TYPE_FTPSSLAUTH, CURLOPT_FTPSSLAUTH);
    FU32TLV(fuzz, TLV_TYPE_FTP_FILEMETHOD, CURLOPT_FTP_FILEMETHOD);
    FU32TLV(fuzz, TLV_TYPE_SSH_AUTH_TYPES, CURLOPT_SSH_AUTH_TYPES);
    FU32TLV(fuzz, TLV_TYPE_POSTREDIR, CURLOPT_POSTREDIR);
    FU32TLV(fuzz, TLV_TYPE_GSSAPI_DELEGATION, CURLOPT_GSSAPI_DELEGATION);
    FU32TLV(fuzz, TLV_TYPE_SSL_OPTIONS, CURLOPT_SSL_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_HEADEROPT, CURLOPT_HEADEROPT);
    FU32TLV(fuzz, TLV_TYPE_PROXY_SSLVERSION, CURLOPT_PROXY_SSLVERSION);
    FU32TLV(fuzz, TLV_TYPE_RESUME_FROM_LARGE, CURLOPT_RESUME_FROM_LARGE);
    FU32TLV(fuzz, TLV_TYPE_MAXFILESIZE_LARGE, CURLOPT_MAXFILESIZE_LARGE);
    // too easy for API misuse FU32TLV(fuzz, TLV_TYPE_POSTFIELDSIZE_LARGE, CURLOPT_POSTFIELDSIZE_LARGE);
    FU32TLV(fuzz, TLV_TYPE_MAX_SEND_SPEED_LARGE, CURLOPT_MAX_SEND_SPEED_LARGE);
    FU32TLV(fuzz, TLV_TYPE_MAX_RECV_SPEED_LARGE, CURLOPT_MAX_RECV_SPEED_LARGE);
    FU32TLV(fuzz, TLV_TYPE_TIMEVALUE_LARGE, CURLOPT_TIMEVALUE_LARGE);

    /* Define a set of singleton TLVs - they can only have their value set once
       and all follow the same pattern. */
    FSINGLETONTLV(fuzz, TLV_TYPE_URL, CURLOPT_URL);
    FSINGLETONTLV(fuzz, TLV_TYPE_DOH_URL, CURLOPT_DOH_URL);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERNAME, CURLOPT_USERNAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_PASSWORD, CURLOPT_PASSWORD);
    FSINGLETONTLV(fuzz, TLV_TYPE_COOKIE, CURLOPT_COOKIE);
    FSINGLETONTLV(fuzz, TLV_TYPE_RANGE, CURLOPT_RANGE);
    FSINGLETONTLV(fuzz, TLV_TYPE_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST);
    FSINGLETONTLV(fuzz, TLV_TYPE_MAIL_FROM, CURLOPT_MAIL_FROM);
    FSINGLETONTLV(fuzz, TLV_TYPE_ACCEPTENCODING, CURLOPT_ACCEPT_ENCODING);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_SESSION_ID, CURLOPT_RTSP_SESSION_ID);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_STREAM_URI, CURLOPT_RTSP_STREAM_URI);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_TRANSPORT, CURLOPT_RTSP_TRANSPORT);
    FSINGLETONTLV(fuzz, TLV_TYPE_MAIL_AUTH, CURLOPT_MAIL_AUTH);
    FSINGLETONTLV(fuzz, TLV_TYPE_LOGIN_OPTIONS, CURLOPT_LOGIN_OPTIONS);
    FSINGLETONTLV(fuzz, TLV_TYPE_XOAUTH2_BEARER, CURLOPT_XOAUTH2_BEARER);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERPWD, CURLOPT_USERPWD);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERAGENT, CURLOPT_USERAGENT);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_HOST_PUBLIC_KEY_SHA256, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY, CURLOPT_PROXY);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXYUSERPWD, CURLOPT_PROXYUSERPWD);
    FSINGLETONTLV(fuzz, TLV_TYPE_REFERER, CURLOPT_REFERER);
    FSINGLETONTLV(fuzz, TLV_TYPE_FTPPORT, CURLOPT_FTPPORT);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSLCERT, CURLOPT_SSLCERT);
    FSINGLETONTLV(fuzz, TLV_TYPE_KEYPASSWD, CURLOPT_KEYPASSWD);
    FSINGLETONTLV(fuzz, TLV_TYPE_INTERFACE, CURLOPT_INTERFACE);
    FSINGLETONTLV(fuzz, TLV_TYPE_KRBLEVEL, CURLOPT_KRBLEVEL);
    FSINGLETONTLV(fuzz, TLV_TYPE_CAINFO, CURLOPT_CAINFO);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSL_CIPHER_LIST, CURLOPT_SSL_CIPHER_LIST);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSLCERTTYPE, CURLOPT_SSLCERTTYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSLKEY, CURLOPT_SSLKEY);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSLKEYTYPE, CURLOPT_SSLKEYTYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSLENGINE, CURLOPT_SSLENGINE);
    FSINGLETONTLV(fuzz, TLV_TYPE_CAPATH, CURLOPT_CAPATH);
    FSINGLETONTLV(fuzz, TLV_TYPE_FTP_ACCOUNT, CURLOPT_FTP_ACCOUNT);
    FSINGLETONTLV(fuzz, TLV_TYPE_COOKIELIST, CURLOPT_COOKIELIST);
    FSINGLETONTLV(fuzz, TLV_TYPE_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_ALTERNATIVE_TO_USER);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_PUBLIC_KEYFILE, CURLOPT_SSH_PUBLIC_KEYFILE);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_PRIVATE_KEYFILE, CURLOPT_SSH_PRIVATE_KEYFILE);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_HOST_PUBLIC_KEY_MD5, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5);
    FSINGLETONTLV(fuzz, TLV_TYPE_ISSUERCERT, CURLOPT_ISSUERCERT);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXYUSERNAME, CURLOPT_PROXYUSERNAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXYPASSWORD, CURLOPT_PROXYPASSWORD);
    FSINGLETONTLV(fuzz, TLV_TYPE_NOPROXY, CURLOPT_NOPROXY);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_KNOWNHOSTS, CURLOPT_SSH_KNOWNHOSTS);
    FSINGLETONTLV(fuzz, TLV_TYPE_TLSAUTH_USERNAME, CURLOPT_TLSAUTH_USERNAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_TLSAUTH_PASSWORD, CURLOPT_TLSAUTH_PASSWORD);
    FSINGLETONTLV(fuzz, TLV_TYPE_TLSAUTH_TYPE, CURLOPT_TLSAUTH_TYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_DNS_SERVERS, CURLOPT_DNS_SERVERS);
    FSINGLETONTLV(fuzz, TLV_TYPE_DNS_INTERFACE, CURLOPT_DNS_INTERFACE);
    FSINGLETONTLV(fuzz, TLV_TYPE_DNS_LOCAL_IP4, CURLOPT_DNS_LOCAL_IP4);
    FSINGLETONTLV(fuzz, TLV_TYPE_DNS_LOCAL_IP6, CURLOPT_DNS_LOCAL_IP6);
    FSINGLETONTLV(fuzz, TLV_TYPE_PINNEDPUBLICKEY, CURLOPT_PINNEDPUBLICKEY);
    FSINGLETONTLV(fuzz, TLV_TYPE_UNIX_SOCKET_PATH, CURLOPT_UNIX_SOCKET_PATH);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SERVICE_NAME, CURLOPT_PROXY_SERVICE_NAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_SERVICE_NAME, CURLOPT_SERVICE_NAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_DEFAULT_PROTOCOL, CURLOPT_DEFAULT_PROTOCOL);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_CAINFO, CURLOPT_PROXY_CAINFO);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_CAPATH, CURLOPT_PROXY_CAPATH);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_TLSAUTH_USERNAME, CURLOPT_PROXY_TLSAUTH_USERNAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_TLSAUTH_PASSWORD, CURLOPT_PROXY_TLSAUTH_PASSWORD);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_TLSAUTH_TYPE, CURLOPT_PROXY_TLSAUTH_TYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SSLCERT, CURLOPT_PROXY_SSLCERT);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SSLCERTTYPE, CURLOPT_PROXY_SSLCERTTYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SSLKEY, CURLOPT_PROXY_SSLKEY);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SSLKEYTYPE, CURLOPT_PROXY_SSLKEYTYPE);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_KEYPASSWD, CURLOPT_PROXY_KEYPASSWD);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_SSL_CIPHER_LIST, CURLOPT_PROXY_SSL_CIPHER_LIST);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_CRLFILE, CURLOPT_PROXY_CRLFILE);
    FSINGLETONTLV(fuzz, TLV_TYPE_PRE_PROXY, CURLOPT_PRE_PROXY);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_PINNEDPUBLICKEY, CURLOPT_PROXY_PINNEDPUBLICKEY);
    FSINGLETONTLV(fuzz, TLV_TYPE_ABSTRACT_UNIX_SOCKET, CURLOPT_ABSTRACT_UNIX_SOCKET);
    FSINGLETONTLV(fuzz, TLV_TYPE_REQUEST_TARGET, CURLOPT_REQUEST_TARGET);
    FSINGLETONTLV(fuzz, TLV_TYPE_TLS13_CIPHERS, CURLOPT_TLS13_CIPHERS);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_TLS13_CIPHERS, CURLOPT_PROXY_TLS13_CIPHERS);
    FSINGLETONTLV(fuzz, TLV_TYPE_SASL_AUTHZID, CURLOPT_SASL_AUTHZID);
    FSINGLETONTLV(fuzz, TLV_TYPE_PROXY_ISSUERCERT, CURLOPT_PROXY_ISSUERCERT);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSL_EC_CURVES, CURLOPT_SSL_EC_CURVES);
    FSINGLETONTLV(fuzz, TLV_TYPE_AWS_SIGV4, CURLOPT_AWS_SIGV4);
    FSINGLETONTLV(fuzz, TLV_TYPE_REDIR_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS_STR);
    FSINGLETONTLV(fuzz, TLV_TYPE_HAPROXY_CLIENT_IP, CURLOPT_HAPROXY_CLIENT_IP);
    FSINGLETONTLV(fuzz, TLV_TYPE_ECH, CURLOPT_ECH);
    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 127;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  fuzz_free((void **)&tmp);

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

/* set up for CURLOPT_HTTPPOST, an alternative API to CURLOPT_MIMEPOST */
void fuzz_setup_http_post(FUZZ_DATA *fuzz, TLV *tlv)
{
  if (fuzz->httppost == NULL) {
    struct curl_httppost *post = NULL;
    struct curl_httppost *last = NULL;

    fuzz->post_body = fuzz_tlv_to_string(tlv);
    if (fuzz->post_body == NULL) {
      return;
    }

    /* This is just one of several possible entrypoints to
     * the HTTPPOST API. see https://curl.se/libcurl/c/curl_formadd.html
     * for lots of others which could be added here.
     */
    curl_formadd(&post, &last,
		 CURLFORM_COPYNAME, FUZZ_HTTPPOST_NAME,
		 CURLFORM_PTRCONTENTS, fuzz->post_body,
		 CURLFORM_CONTENTLEN, (curl_off_t) strlen(fuzz->post_body),
		 CURLFORM_END);

    fuzz->last_post_part = last;
    fuzz->httppost = post;
  }

  return;
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
