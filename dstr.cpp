#include "dstr.h"

int DStrCreate(DStr *pDStr, uint32_t capacity) {
    int ret = 0;
    do {
        if (pDStr == NULL) {
            break;
        }
        InitializeCriticalSection(&pDStr->cs);
        pDStr->len = 0;
        pDStr->capacity = capacity;
		if (pDStr->pStorage != NULL) {
			Free(pDStr->pStorage);
			pDStr->pStorage = NULL;
		}
		if (capacity > 0) {
			pDStr->pStorage = Malloc(capacity);
			if (NULL == pDStr->pStorage) {
				Memset(pDStr->pStorage, 0, sizeof(DStr));
				break;
			}
			else {
				ret = 1;
			}
		}
		else {
			ret = 1;
		}
    } while (0);
    return(ret);
}

int DStrClone(DStr *pDStrDst, DStr *pDStrSrc) {
	int ret = 0;
	if (pDStrDst != NULL && pDStrSrc != NULL) {
		EnterCriticalSection(&pDStrSrc->cs);
		do {
			if ((ret = DStrCreate(pDStrDst, pDStrSrc->capacity)) == 0) {
				break;
			}
			if (pDStrSrc->len) {
				Memcpy(pDStrDst->pStorage, pDStrSrc->pStorage, pDStrSrc->len);
				pDStrDst->len = pDStrSrc->len;
			}
		} while (0);
		LeaveCriticalSection(&pDStrSrc->cs);
	}
	return(ret);
}

int DStrDestroy(DStr *pDStr) {
    int ret = 0;
    do {
        if (pDStr == NULL) {
            break;
        }
        if (pDStr->pStorage != NULL) {
			Memset(pDStr->pStorage, 0, sizeof(DStr));
            Free(pDStr->pStorage);
        }
        DeleteCriticalSection(&pDStr->cs);
		Memset(pDStr, 0, sizeof(DStr));
        ret = 1;
    } while(0);
    return(ret);
}

int DStrGetLen(DStr *pDStr, uint32_t *pLen) {
	int ret = 0;
	if (pDStr != NULL && pLen != NULL) {
		EnterCriticalSection(&pDStr->cs);
		*pLen = pDStr->len;
		LeaveCriticalSection(&pDStr->cs);
		ret = 1;
	}
	return(ret);
}

int DStrSkip(DStr *pDStr, unsigned len) {
	int res = 0;
	uint32_t temp = 0;
	do {
		if (pDStr == NULL || len == 0) {
			break;
		}
		EnterCriticalSection(&pDStr->cs);
		do {
			if (len > pDStr->len) {
				break;
			}
			temp = pDStr->len - len;
			if (temp > 0) {
				Memcpy(pDStr->pStorage, &((char *)pDStr->pStorage)[len], temp);
			}
			pDStr->len = temp;
			res = 1;
		} while (0);
		LeaveCriticalSection(&pDStr->cs);
	} while (0);
	return(res);
}

int DStrAppend(DStr *pDStr, void *pData, unsigned uDataLen) {
    int ret = 0;
    do {
        if (pDStr == NULL || pData == NULL || uDataLen == 0) {
            break;
        }
        EnterCriticalSection(&pDStr->cs);
        do {
            void *pTemp = NULL;
            uint32_t uTemp = uDataLen + pDStr->len;
            uTemp = ((uTemp + MEMORYSTORAGE_STEP - 1) / MEMORYSTORAGE_STEP) * MEMORYSTORAGE_STEP;
            if (uTemp > pDStr->capacity) {
                pTemp = ReAlloc(pDStr->pStorage, uTemp);
                if (pTemp == NULL) {
					pDStr->capacity = 0;
					pDStr->len = 0;
                }
                else {
                    Memcpy(((char *)pTemp) + pDStr->len, pData, uDataLen);
					pDStr->len = uDataLen + pDStr->len;
					pDStr->capacity = uTemp;
					pDStr->pStorage = pTemp;
                    ret = 1;
                }
            } else {
                Memcpy(((char *)pDStr->pStorage) + pDStr->len, pData, uDataLen);
				pDStr->len += uDataLen;
                pData = NULL;
                ret = 1;
            }
        } while(0);
        LeaveCriticalSection(&pDStr->cs);
    } while (0);
    return(ret);
}

int DStrUtf8CatA(DStr *pDStr, char *szText) {
	if (szText == NULL || pDStr == NULL) {
		return(0);
	}
	return(DStrAppend(pDStr, szText, StrlenA(szText)));
}

int DStrUtf16CatW(DStr *pDStr, wchar_t *szText) {
	if (szText == NULL || pDStr == NULL) {
		return(0);
	}
	return(DStrAppend(pDStr, szText, StrlenW(szText)*sizeof(wchar_t)));
}

int DStrUtf8CatW(DStr *pDStr, wchar_t *szText) {
	int ret = 0;
	char *szTemp = NULL;
	do {
		if (szText == NULL || pDStr == NULL) {
			break;
		}
		if ((szTemp = StrUtf16ToUtf8(szText)) != NULL) {
			ret = DStrUtf8CatA(pDStr, szTemp);
			Free(szTemp);
		}
	} while (0);
	return(ret);
}

int DStrUtf16CatA(DStr *pDStr, char *szText) {
	int ret = 0;
	wchar_t *szTemp = NULL;
	do {
		if (szText == NULL || pDStr == NULL) {
			break;
		}
		if ((szTemp = StrUtf8ToUtf16(szText)) != NULL) {
			ret = DStrUtf16CatW(pDStr, szTemp);
			Free(szTemp);
		}
	} while (0);
	return(ret);
}
