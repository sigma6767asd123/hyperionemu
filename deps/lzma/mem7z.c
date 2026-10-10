#include "Precomp.h"

#include <string.h>

#include "7z.h"
#include "7zAlloc.h"
#include "7zCrc.h"
#include "7zTypes.h"
#include "mem7z.h"

typedef struct {
    ILookInStream vt;
    const Byte *data;
    size_t size;
    size_t pos;
} CMemInStream;

static SRes
Mem_Look(ILookInStreamPtr pp, const void **buf, size_t *size)
{
    CMemInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemInStream, vt);
    size_t rem = p->size - p->pos;
    if (*size > rem) {
        *size = rem;
    }
    *buf = p->data + p->pos;
    return SZ_OK;
}

static SRes
Mem_Skip(ILookInStreamPtr pp, size_t offset)
{
    CMemInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemInStream, vt);
    p->pos += offset;
    return SZ_OK;
}

static SRes
Mem_Read(ILookInStreamPtr pp, void *buf, size_t *size)
{
    CMemInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemInStream, vt);
    size_t rem = p->size - p->pos;
    if (*size > rem) {
        *size = rem;
    }
    memcpy(buf, p->data + p->pos, *size);
    p->pos += *size;
    return SZ_OK;
}

static SRes
Mem_Seek(ILookInStreamPtr pp, Int64 *pos, ESzSeek origin)
{
    CMemInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemInStream, vt);
    Int64 neu = 0;

    if (origin == SZ_SEEK_SET) {
        neu = *pos;
    } else if (origin == SZ_SEEK_CUR) {
        neu = (Int64)p->pos + *pos;
    } else if (origin == SZ_SEEK_END) {
        neu = (Int64)p->size + *pos;
    } else {
        return SZ_ERROR_PARAM;
    }
    if (neu < 0 || (UInt64)neu > p->size) {
        return SZ_ERROR_PARAM;
    }
    p->pos = (size_t)neu;
    *pos = neu;
    return SZ_OK;
}

static void
Mem_Init(CMemInStream *p, const Byte *data, size_t size)
{
    p->vt.Look = Mem_Look;
    p->vt.Skip = Mem_Skip;
    p->vt.Read = Mem_Read;
    p->vt.Seek = Mem_Seek;
    p->data = data;
    p->size = size;
    p->pos = 0;
}

int
Mem7zExtract(const void *Src, size_t SrcLen, void *Dst, size_t DstLen)
{
    static const ISzAlloc kAlloc = { SzAlloc, SzFree };
    static const ISzAlloc kAllocTemp = { SzAllocTemp, SzFreeTemp };
    CMemInStream mem;
    CSzArEx db;
    SRes res;
    UInt32 blockIndex = 0xFFFFFFFF;
    Byte *outBuffer = NULL;
    size_t outBufferSize = 0;
    size_t offset = 0;
    size_t outSizeProcessed = 0;
    UInt32 i;
    int found = 0;

    if (!Src || !Dst || !SrcLen || !DstLen) {
        return 0;
    }

    CrcGenerateTable();
    Mem_Init(&mem, (const Byte *)Src, SrcLen);
    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &mem.vt, &kAlloc, &kAllocTemp);
    if (res != SZ_OK) {
        SzArEx_Free(&db, &kAlloc);
        return 0;
    }

    for (i = 0; i < db.NumFiles; i++) {
        if (SzArEx_IsDir(&db, i)) {
            continue;
        }
        if (SzArEx_GetFileSize(&db, i) != DstLen) {
            continue;
        }
        res = SzArEx_Extract(&db, &mem.vt, i, &blockIndex, &outBuffer, &outBufferSize, &offset, &outSizeProcessed, &kAlloc, &kAllocTemp);
        if (res != SZ_OK || outSizeProcessed != DstLen) {
            break;
        }
        memcpy(Dst, outBuffer + offset, DstLen);
        found = 1;
        break;
    }

    ISzAlloc_Free(&kAlloc, outBuffer);
    SzArEx_Free(&db, &kAlloc);
    return found;
}
