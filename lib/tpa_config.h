/*
 * Copyright (C) 2010 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
 
#ifndef TPA_CONFIG_H
#define TPA_CONFIG_H

#include "sklog_define.h"

#define     NONCE_LEN           SHA1_LEN

#define     SRKPWD              "srkpwd"
#define     AIKPWD              "aikpwd"

#define     SK_AIK_ID           1
#define     SK_PCR_TO_EXTEND    13

#endif /* TPA_CONFIG_H */
