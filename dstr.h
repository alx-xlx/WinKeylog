#pragma once
#include "tools.h"

typedef struct _DStr {
    CRITICAL_SECTION cs;
    void *pStorage;
    uint32_t len;
    uint32_t capacity;
} DStr;

#define MEMORYSTORAGE_STEP 0x1000

int DStrCreate(DStr *pDStr, uint32_t capacity);
int DStrDestroy(DStr *pDStr);
int DStrAppend(DStr *pDStr, void *pData, unsigned uDataLen);
int DStrGetLen(DStr *pDStr, uint32_t *pLen);
int DStrClone(DStr *pDStrDst, DStr *pDStrSrc);
int DStrSkip(DStr *pDStr, unsigned len);
int DStrUtf8CatA(DStr *pDStr, char *szText);
int DStrUtf16CatW(DStr *pDStr, wchar_t *szText);
int DStrUtf8CatW(DStr *pDStr, wchar_t *szText);
int DStrUtf16CatA(DStr *pDStr, char *szText);
