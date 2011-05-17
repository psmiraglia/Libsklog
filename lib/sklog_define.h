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
**    the Free Software Foundation, either version 3 of the License, or
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

#ifndef SKLOG_DEFINE_H
#define SKLOG_DEFINE_H

#define     SHA1_LEN            20
#define     SHA256_LEN          32
#define     BUFFER_LEN          1024
#define     NONCE_LEN           SHA1_LEN

#define     SK_HASH_CHAIN_LEN   SHA256_LEN
#define     SK_ENC_KEY_LEN      SHA256_LEN
#define     SK_HMAC_LEN         SHA256_LEN
#define     SK_AUTH_KEY_LEN     SHA256_LEN

#define     SK_SUCCESS          0
#define     SK_FAILURE          !SK_SUCCESS

#define     TPM_CONFIG_FILE     ETC_PREFIX"/libsklog/tpm.conf"

#endif /* SKLOG_DEFINE_H */
