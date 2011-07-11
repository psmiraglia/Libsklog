#ifndef SKLOG_UTILS_H
#define SKLOG_UTILS_H

#include <openssl/rsa.h>

SKLOG_RETURN
SKLOG_Utils_SerializeLogentry(SKLOG_LE *,
                              unsigned char **,
                              unsigned int *);
                              
SKLOG_RETURN
SKLOG_Utils_DeserializeLogentry(unsigned char *,
                                unsigned int,
                                SKLOG_LE *);

#endif /* SKLOG_UTILS_H */
