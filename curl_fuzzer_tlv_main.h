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
#define TLV_TYPE_URL                    	1
#define TLV_TYPE_RESPONSE0              	2
#define TLV_TYPE_USERNAME               	3
#define TLV_TYPE_PASSWORD               	4
#define TLV_TYPE_POSTFIELDS             	5
#define TLV_TYPE_HEADER                 	6
#define TLV_TYPE_COOKIE                 	7
#define TLV_TYPE_UPLOAD1                	8
#define TLV_TYPE_RANGE                  	9
#define TLV_TYPE_CUSTOMREQUEST          	10
#define TLV_TYPE_MAIL_RECIPIENT         	11
#define TLV_TYPE_MAIL_FROM              	12
#define TLV_TYPE_MIME_PART              	13
#define TLV_TYPE_MIME_PART_NAME         	14
#define TLV_TYPE_MIME_PART_DATA         	15
#define TLV_TYPE_HTTPAUTH               	16
#define TLV_TYPE_RESPONSE1              	17
#define TLV_TYPE_RESPONSE2              	18
#define TLV_TYPE_RESPONSE3              	19
#define TLV_TYPE_RESPONSE4              	20
#define TLV_TYPE_RESPONSE5              	21
#define TLV_TYPE_RESPONSE6              	22
#define TLV_TYPE_RESPONSE7              	23
#define TLV_TYPE_RESPONSE8              	24
#define TLV_TYPE_RESPONSE9              	25
#define TLV_TYPE_RESPONSE10             	26
#define TLV_TYPE_OPTHEADER              	27
#define TLV_TYPE_NOBODY                 	28
#define TLV_TYPE_FOLLOWLOCATION         	29
#define TLV_TYPE_ACCEPTENCODING         	30
#define TLV_TYPE_SECOND_RESPONSE0       	31
#define TLV_TYPE_SECOND_RESPONSE1       	32
#define TLV_TYPE_WILDCARDMATCH          	33
#define TLV_TYPE_RTSP_REQUEST           	34
#define TLV_TYPE_RTSP_SESSION_ID        	35
#define TLV_TYPE_RTSP_STREAM_URI        	36
#define TLV_TYPE_RTSP_TRANSPORT         	37
#define TLV_TYPE_RTSP_CLIENT_CSEQ       	38
#define TLV_TYPE_MAIL_AUTH              	39
#define TLV_TYPE_HTTP_VERSION           	40
#define TLV_TYPE_DOH_URL                	41
#define TLV_TYPE_LOGIN_OPTIONS          	42
#define TLV_TYPE_XOAUTH2_BEARER         	43
#define TLV_TYPE_USERPWD                	44
#define TLV_TYPE_USERAGENT              	45
#define TLV_TYPE_NETRC                  	46
#define TLV_TYPE_SSH_HOST_PUBLIC_KEY_SHA256	47
#define TLV_TYPE_POST                   	48
#define TLV_TYPE_WS_OPTIONS             	49
#define TLV_TYPE_CONNECT_ONLY           	50
#define TLV_TYPE_HSTS                   	51
#define TLV_TYPE_HTTPPOSTBODY           	52

typedef struct fuzz_data_main FUZZ_DATA;