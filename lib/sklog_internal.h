/*
**    Copyright (C) 2011 Politecnico di Torino, Italy
**
**        TORSEC group -- http://security.polito.it
**        Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
**
**    This file is part of Libsklog.
**
**    Libsklog is free software: you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation; either version 2 of the License, or
**    (at your option) any later version.
**
**    Libsklog is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    You should have received a copy of the GNU General Public License
**    along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SKLOG_INTERNAL_H
#define SKLOG_INTERNAL_H

#include "sklog_commons.h"

#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

SKLOG_RETURN
sign_message(unsigned char    *message,
             unsigned int     message_len,
             EVP_PKEY         *signing_key,
             unsigned char    **signature,
             unsigned int     *signature_len);

SKLOG_RETURN
sign_verify(EVP_PKEY         *verify_key,
            unsigned char    *signature,
            size_t           signature_len,
            unsigned char    *message,
            unsigned int     message_len);

SKLOG_RETURN
pke_encrypt(X509             *cert,   
            unsigned char    *in,
            unsigned char    in_len,
            unsigned char    **out,
            size_t           *out_len);

SKLOG_RETURN
pke_decrypt(EVP_PKEY         *key,
            unsigned char    *in,
            size_t           in_len,
            unsigned char    **out,
            size_t           *out_len);

SKLOG_RETURN
encrypt_aes256(unsigned char    **data_enc,
               unsigned int     *data_enc_size,
               unsigned char    *data,
               unsigned int     data_size,
               unsigned char    *enc_key);

SKLOG_RETURN
decrypt_aes256(unsigned char    *dec_key,
               unsigned char    *in,
               unsigned int     in_len,
               unsigned char    **out,
               unsigned int     *out_len);

SKLOG_RETURN
tlv_create(uint32_t         type,
           unsigned int     data_len,
           void             *data,
           unsigned char    *buffer);

SKLOG_RETURN
tlv_parse(unsigned char    *tlv_msg,
          uint32_t         type,
          void             *data,
          unsigned int     *data_len);

SKLOG_RETURN
tlv_get_type(unsigned char    *tlv_msg,
             uint32_t         *type);

SKLOG_RETURN
tlv_get_len(unsigned char    *tlv_msg,
            unsigned int     *len);

SKLOG_RETURN
tlv_get_value(unsigned char    *tlv_msg,
              unsigned int     len,
              unsigned char    **value);

SKLOG_RETURN
serialize_timeval(struct timeval    *time,
                  unsigned char     **buf,
                  unsigned int      *buf_len);

SKLOG_RETURN
deserialize_timeval(unsigned char     *buf,
                    unsigned int      buf_len,
                    struct timeval    *time);

#endif /* SKLOG_INTERNAL_H */
