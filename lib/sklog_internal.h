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

#include <uuid/uuid.h>

/*--------------------------------------------------------------------*/
/*                         crypto primitives                          */
/*--------------------------------------------------------------------*/

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
aes256_encrypt(unsigned char    *plain,
               unsigned int     plain_len,
               unsigned char    *key,
               unsigned int     key_len,
               unsigned char    **cipher,
               unsigned int     *cipher_len);

SKLOG_RETURN
aes256_decrypt(unsigned char    *cipher,
               unsigned int     cipher_len,
               unsigned char    *key,
               unsigned int     key_len,
               unsigned char    **plain,
               unsigned int     *plain_len);

SKLOG_RETURN
sha256(unsigned char    *message,
       unsigned int     message_len,
       unsigned char    *hash,
       unsigned int     *hash_len);

SKLOG_RETURN
hmac(unsigned char    *message,
     unsigned int     message_len,
     unsigned char    *key,
     unsigned int     key_len,
     unsigned char    *hmac,
     unsigned int     *hmac_len);

SKLOG_RETURN
b64_enc(unsigned char    *blob,
        unsigned int     blob_len,
        char             **b64_blob);

SKLOG_RETURN
b64_dec(char    *b64_blob,
        unsigned int     b64_blob_len,
        unsigned char    **blob,
        unsigned int     *blob_len);
/*--------------------------------------------------------------------*/
/*                         tlv management                             */
/*--------------------------------------------------------------------*/

//~ SKLOG_RETURN
//~ tlv_create(uint32_t         type,
           //~ unsigned int     data_len,
           //~ void             *data,
           //~ unsigned char    *buffer);

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
              unsigned char    **value);

SKLOG_RETURN
tlv_parse_message(unsigned char    *msg,
                  uint32_t         exected_type,
                  uint32_t         *type,
                  unsigned int     *len,
                  unsigned char    **value);

SKLOG_RETURN
tlv_create_message(uint32_t         type,
                   unsigned int     len,
                   unsigned char    *value,
                   unsigned char    **message,
                   unsigned int     *message_len);

/*--------------------------------------------------------------------*/
/*                      timestamp management                          */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
serialize_timeval(struct timeval    *time,
                  unsigned char     **buf,
                  unsigned int      *buf_len);

SKLOG_RETURN
deserialize_timeval(unsigned char     *buf,
                    unsigned int      buf_len,
                    struct timeval    *time);
                    
/*--------------------------------------------------------------------*/
/*                       memory management                            */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
mem_alloc_n(void      **mem,
            size_t    size,
            size_t    couny);

SKLOG_RETURN
mem_free(void      **mem);

/*--------------------------------------------------------------------*/
/*                    logfile flush management                        */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
#ifdef USE_SSL
flush_logfile_send_logentry(SSL              *ssl,
#endif
#ifdef USE_BIO
flush_logfile_send_logentry(BIO              *bio,
#endif
                            char             *f_uuid,
                            unsigned char    *type,
                            unsigned int     type_len,
                            unsigned char    *data_enc,
                            unsigned int     data_enc_len,
                            unsigned char    *y,
                            unsigned int     y_len,
                            unsigned char    *z,
                            unsigned int     z_len);

/*--------------------------------------------------------------------*/
/*                         conenctions                                */
/*--------------------------------------------------------------------*/

SKLOG_CONNECTION*
new_connection(void);

SKLOG_RETURN
free_conenction(SKLOG_CONNECTION *c);

SKLOG_RETURN
setup_ssl_connection(SKLOG_CONNECTION    *c,
                     const char          *s_addr,
                     short int           s_port,
                 //~ const char          *cert_file_path,
                     X509                *cert,
                 //~ const char          *key_file_path,
                     EVP_PKEY            *privkey,
                     const char          *cacert_file_path,
                     int                 enable_verify);

SKLOG_RETURN
destroy_ssl_connection(SKLOG_CONNECTION *c);                     

//~ SSL_CTX*
//~ init_ssl_ctx(const char    *cert_file_path,
             //~ const char    *key_file_path,
             //~ const char    *ca_file_path,
             //~ int           enable_verify);


//~ SSL*
//~ init_ssl_structure_s(SSL_CTX    *ctx,
                     //~ int        socket,
                     //~ int        verify);

//~ SSL*
//~ init_ssl_structure_c(SSL_CTX    *ctx,
                     //~ int        socket);

int
tcp_bind(const char    *address,
         short int     port);
int
tcp_connect(const char    *address,
            short int     port);

//~ int
//~ sock_connect(const char *s_addr,
             //~ short int s_port);

//~ SKLOG_RETURN
//~ conn_close(SKLOG_CONNECTION    *conn);

/*--------------------------------------------------------------------*/
/*                      user messages management                      */
/*--------------------------------------------------------------------*/

#define TERM_LINE 72

void
sklog_msg_to_implement(const char *f);

void
sklog_show_buffer(int pid,
				  const char *file,
				  int line,
				  const char *func,
				  const char *bufname,
				  unsigned char *buf,
				  unsigned int bufl);

/*--------------------------------------------------------------------*/
/*                              uuid                                  */
/*--------------------------------------------------------------------*/

int sklog_uuid_unparse(uuid_t u, char *out);

void write2file(const char *file, const char *mode, unsigned char *buf, unsigned int bufl);
#endif /* SKLOG_INTERNAL_H */
