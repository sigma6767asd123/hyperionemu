#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int Mem7zExtract(const void *Src, size_t SrcLen, void *Dst, size_t DstLen);

#ifdef __cplusplus
}
#endif
