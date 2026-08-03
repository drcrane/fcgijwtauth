#ifndef MINISHA256_H
#define MINISHA256_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void sha256_buf(void * buf, size_t buf_len, char output_buffer[65]);

#ifdef __cplusplus
}
#endif

#endif // MINISHA256_H

