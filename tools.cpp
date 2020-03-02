#pragma once
#include "tools.h"

void *hHeap = NULL;

void InitTools() {
    hHeap = GetProcessHeap();
}

void *Malloc(size_t sz) {
	return(HeapAlloc(hHeap, 0, sz));
}

void *ReAlloc(void *p, size_t newsz) {
	void *ret = NULL;
	if (p == NULL) {
		ret = Malloc(newsz);
	}
	else if (HeapValidate(hHeap, 0, p)) {
		ret = HeapReAlloc(hHeap, 0, p, newsz);
	}
	return(ret);
}

void Free(void *p) {
	if (p != NULL && HeapValidate(hHeap, 0, p)) {
		HeapFree(hHeap, 0, p);
	}
}

void Memcpy(void *dst, void *src, size_t len) {
	for (size_t i = 0; i < len; i++) {
		((uint8_t *)dst)[i] = ((uint8_t *)src)[i];
	}
}

void Memset(void *dst, uint8_t val, size_t len) {
	for (size_t i = 0; i < len; i++) {
		((uint8_t *)dst)[i] = val;
	}
}

size_t StrlenA(char *src) {
	size_t len = 0;
	while(src != NULL && *src != 0) {
		len++;
		src++;
	}
	return(len);
}

size_t StrlenW(wchar_t *src) {
	size_t len = 0;
	while (src != NULL && *src != 0) {
		len++;
		src++;
	}
	return(len);
}

size_t StrnlenA(char *src, size_t n) {
	size_t len = 0;
	while (src != NULL && *src != 0 && n != 0) {
		len++;
		src++;
		n--;
	}
	return(len);
}

size_t StrnlenW(wchar_t *src, size_t n) {
	size_t len = 0;
	while (src != NULL && *src != 0 && n != 0) {
		len++;
		src++;
		n--;
	}
	return(len);
}

char *StrdupA(char *src) {
	char *res = NULL;
	size_t len = 0;
	if (src == NULL) {
		return(NULL);
	}
	len = StrlenA(src);
	if ((res = (char *)Malloc(len+1)) != NULL) {
		Memcpy(res, src, len);
		res[len] = 0;
	}
	return(res);
}

wchar_t *StrdupW(wchar_t *src) {
	wchar_t *res = NULL;
	size_t len = 0;
	if (src == NULL) {
		return(NULL);
	}
	len = StrlenW(src);
	if ((res = (wchar_t *)Malloc(sizeof(wchar_t)*(len + 1))) != NULL) {
		Memcpy(res, src, sizeof(wchar_t)*len);
		res[len] = 0;
	}
	return(res);
}

wchar_t *StrndupW(wchar_t *src, unsigned n) {
	wchar_t *res = NULL;
	size_t len = 0;
	if (src == NULL) {
		return(NULL);
	}
	len = StrnlenW(src, n);
	if ((res = (wchar_t *)Malloc(sizeof(wchar_t)*(len + 1))) != NULL) {
		Memcpy(res, src, sizeof(wchar_t)*len);
		res[len] = 0;
	}
	return(res);
}

void StrcatA(char *dst, char *src) {
	if (dst != NULL && src != NULL) {
		size_t dstlen = StrlenA(dst);
		size_t srclen = StrlenA(src);
		Memcpy(&dst[dstlen], src, srclen);
		dst[dstlen + srclen] = 0;
	}
}

void StrcatW(wchar_t *dst, wchar_t *src) {
	if (dst != NULL && src != NULL) {
		size_t dstlen = StrlenW(dst);
		size_t srclen = StrlenW(src);
		Memcpy(&dst[dstlen], src, srclen*sizeof(wchar_t));
		dst[dstlen + srclen] = 0;
	}
}

wchar_t *StrUtf8ToUtf16(char *src) {
	size_t len = 0;
	wchar_t *res = NULL;
	do {
		if (src == NULL) {
			break;
		}
		if (!(len = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0))) {
			break;
		}
		if ((res = (wchar_t *)Malloc(sizeof(wchar_t)*len)) == NULL) {
			break;
		};
		MultiByteToWideChar(CP_UTF8, 0, src, -1, res, len);
	} while (0);
	return(res);
}

char *StrUtf16ToUtf8(wchar_t *src) {
	size_t len = 0;
	char *res = NULL;
	do {
		if (src == NULL) {
			break;
		}
		if (!(len = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL))) {
			break;
		}
		if ((res = (char *)Malloc(len)) == NULL) {
			break;
		}
		WideCharToMultiByte(CP_UTF8, 0, src, -1, res, len, NULL, NULL);
	} while (0);
	return(res);
}

unsigned Crc32(void *msg, size_t len) {
	int i, j;
	unsigned byte, crc, mask;
	if ((msg == NULL) || (len == 0)) {
		return(0);
	}
	i = 0;
	crc = 0xFFFFFFFF;
	while (len) {
		byte = ((unsigned char *)msg)[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {
			mask = (unsigned)-((signed)(crc & 1));
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
		len--;
	}
	return ~crc;
}

void RC4(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result) {
	unsigned char T[256];
	unsigned char S[256];
	unsigned char  tmp;
	int j = 0, t = 0, i = 0;
	for (int i = 0; i < 256; i++) {
		S[i] = i;
		T[i] = key[i % keyLen];
	}
	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + T[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
	}
	j = 0;
	for (int x = 0; x< dataLen; x++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
		t = (S[i] + S[j]) % 256;
		result[x] = data[x] ^ S[t];
	}
}

uint64_t GetBotId() {
	OSVERSIONINFOEXW osver;
	MEMORYSTATUSEX statex;
	SYSTEM_INFO sysinfo;
	union {
		uint64_t u64;
		uint32_t u32[2];
	} res;
	res.u64 = 0;
	wchar_t wszBuff[0x100];
	DWORD dwLen = 0;//
	dwLen = sizeof(wszBuff) / sizeof(wchar_t);
	GetUserNameW(wszBuff, &dwLen);
	res.u32[0] = Crc32(wszBuff, StrlenW(wszBuff)*sizeof(wchar_t));
	dwLen = sizeof(wszBuff) / sizeof(wchar_t);
	GetComputerNameW(wszBuff, &dwLen);
	res.u32[1] = Crc32(wszBuff, StrlenW(wszBuff) * sizeof(wchar_t));
	GetWindowsVersion(&osver);
	GetNativeSystemInfo(&sysinfo);
	res.u32[0] ^= osver.dwMinorVersion;
	res.u32[1] ^= osver.dwMajorVersion;
	res.u32[0] ^= sysinfo.dwNumberOfProcessors << 0x4;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	res.u64 ^= statex.ullTotalPhys;
	return(res.u64);
}

wchar_t *ExpandEnvStrW(wchar_t *str) {
	wchar_t *res = NULL;
	do {
		if (str == NULL) {
			break;
		}
		if ((res = (wchar_t *)Malloc(0x800)) == NULL) {
			break;
		}
		ExpandEnvironmentStringsW(str, res, 0x400);
	} while (0);
	return(res);
}

void GetWindowsVersion(POSVERSIONINFOEXW pOsver) {
	HMODULE hNtdll = NULL;
	fncRtlGetVersion pRtlGetVersion = NULL;
	do {
		if (pOsver == NULL) {
			break;
		}
		if ((hNtdll = GetModuleHandleA("ntdll")) == NULL) {
			break;
		}
		if ((pRtlGetVersion = (fncRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion")) == NULL) {
			break;
		}
		Memset(pOsver, 0, sizeof(OSVERSIONINFOEXW));
		pOsver->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		pRtlGetVersion(pOsver);
	} while (0);
}

char *GetOSVersionString() {
	char szBuff[0x40];
	OSVERSIONINFOEXW osver;
	SYSTEM_INFO sysinfo;
	GetWindowsVersion(&osver);
	GetNativeSystemInfo(&sysinfo);
	szBuff[0] = 0;
	StrcatA(szBuff, "Microsoft Windows ");
	char *osverstr = NULL;
	switch (osver.dwMajorVersion) {
		case 5: {
			if (osver.dwMinorVersion == 1) {
				osverstr = "XP";
			}
			else if (osver.dwMinorVersion == 2) {
				if (osver.wSuiteMask & VER_SUITE_WH_SERVER) {
					osverstr = "Home Server";
				}
				else if ((osver.wProductType == VER_NT_WORKSTATION) && (sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)) {
					osverstr = "XP Professional";
				}
				else {
					osverstr = (GetSystemMetrics(SM_SERVERR2)) ? "Server 2003 R2" : "Server 2003";
				}
			}
		}
		break;
		case 6: {
			if (osver.dwMinorVersion == 0) {
				osverstr = (osver.wProductType == VER_NT_WORKSTATION) ? "Vista" : "Server 2008";
			}
			else if (osver.dwMinorVersion == 1) {
				osverstr = (osver.wProductType == VER_NT_WORKSTATION) ? "7" : "Server 2008 R2";
			}
			else if (osver.dwMinorVersion == 2) {
				osverstr = (osver.wProductType == VER_NT_WORKSTATION) ? "8" : "Server 2012";
			}
			else if (osver.dwMinorVersion == 3) {
				osverstr = (osver.wProductType == VER_NT_WORKSTATION) ? "8.1" : "Server 2012 R2";
			}
		}
		break;
		case 10: {
			if (osver.dwMinorVersion == 0) {
				osverstr = (osver.wProductType == VER_NT_WORKSTATION) ? "10" : "Server 2016";
			}
		}
		break;
	}
	osverstr = (osverstr == NULL) ? "UNKNOWN" : osverstr;
	StrcatA(szBuff, osverstr);
	unsigned len = StrlenA(szBuff);
	if (osver.wServicePackMajor || osver.wServicePackMinor) {
		if (osver.wServicePackMinor) {
			wsprintfA(&szBuff[len], " SP%d.%d", osver.wServicePackMajor, osver.wServicePackMinor);
		}
		else {
			wsprintfA(&szBuff[len], " SP%d", osver.wServicePackMajor);
		}
	}
	osverstr = StrdupA(szBuff);
	return(osverstr);
}

void *ReadOverlay(size_t *pLen) {
	void *pOverlay = NULL;
	void *pImage = NULL;
	DWORD dwImageSize = 0;
	HANDLE hFile = NULL;
	DWORD dwRead = 0;
	LARGE_INTEGER liFileSize;
	wchar_t wszBuff[0x400];
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	Memset(wszBuff, 0, sizeof(wszBuff));
	do {
		if (pLen == NULL) {
			break;
		}
		GetModuleFileNameW(NULL, wszBuff, sizeof(wszBuff));
		hFile = CreateFileW(wszBuff, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			break;
		}
		if (!GetFileSizeEx(hFile, &liFileSize)) {
			break;
		}
		if ((liFileSize.HighPart > 0) || (liFileSize.LowPart == 0)) {
			break;
		}
		dwImageSize = liFileSize.LowPart;
		if ((pImage = Malloc(dwImageSize)) == NULL) {
			break;
		}
		if (!ReadFile(hFile, pImage, dwImageSize, &dwRead, NULL) || (dwRead != dwImageSize)) {
			break;
		}
		if (((IMAGE_DOS_HEADER *)pImage)->e_magic != IMAGE_DOS_SIGNATURE) {
			break;
		}
		pNtHeaders = (PIMAGE_NT_HEADERS)(((IMAGE_DOS_HEADER *)pImage)->e_lfanew + (uintptr_t)pImage);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			break;
		}
		PIMAGE_SECTION_HEADER lastSection = &((PIMAGE_SECTION_HEADER)(&pNtHeaders->OptionalHeader.DataDirectory[pNtHeaders->OptionalHeader.NumberOfRvaAndSizes]))[pNtHeaders->FileHeader.NumberOfSections - 1];
		unsigned uPurePESize = lastSection->PointerToRawData + (lastSection->SizeOfRawData & (~(pNtHeaders->OptionalHeader.FileAlignment - 1)));
		if (uPurePESize >= dwImageSize) {
			break;
		}
		size_t len = dwImageSize - uPurePESize;
		if ((pOverlay = Malloc(len)) == NULL) {
			break;
		}
		Memcpy(pOverlay, &((char *)pImage)[uPurePESize], len);
		*pLen = len;
	} while (0);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	if (pImage != NULL) {
		Free(pImage);
	}
	return(pOverlay);
}

#define TICKS_PER_SECOND 10000000
#define UNIX_TIME_START 11644473600LL
uint64_t GetUnixTime() {
	LARGE_INTEGER li;
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft); //returns ticks in UTC
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	return (li.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND;
}
#undef UNIX_TIME_START
#undef TICKS_PER_SECOND