#pragma once
#include <stdint.h>
#include <windows.h>

typedef void(WINAPI *fncRtlGetVersion)(POSVERSIONINFOEXW);

void InitTools();
void *Malloc(size_t sz);
void *ReAlloc(void *p, size_t sz);
void Free(void *p);
void Memcpy(void *dst, void *src, size_t len);
void Memset(void *dst, uint8_t val, size_t len);
size_t StrlenA(char *src);
size_t StrlenW(wchar_t *src);
size_t StrnlenA(char *src, size_t n);
size_t StrnlenW(wchar_t *src, size_t n);
wchar_t *StrUtf8ToUtf16(char *src);
char *StrUtf16ToUtf8(wchar_t *src);
unsigned Crc32(void *msg, size_t len);
uint64_t GetBotId();
void StrcatA(char *dst, char *src);
void StrcatW(wchar_t *dst, wchar_t *src);
wchar_t *StrdupW(wchar_t *src);
wchar_t *StrndupW(wchar_t *src, unsigned n);
void RC4(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result);
wchar_t *ExpandEnvStrW(wchar_t *str);
void GetWindowsVersion(POSVERSIONINFOEXW pOsver);
char *GetOSVersionString();
void *ReadOverlay(size_t *pLen);
uint64_t GetUnixTime();