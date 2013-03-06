#ifndef _UTIL_H_123123123123
#define _UTIL_H_123123123123

#include <stdio.h>

inline int GetVolumnByZeroBasedIndexA(int base, char *szVol, int nVol)
{
	if(nVol < 2) {
		return -1;
	}
	memset(szVol, base + 97, 1);
	memset(szVol + 1, 0, 1);

	return 0;
}

inline int GetVolumnByZeroBasedIndexW(int base, WCHAR *szVol, int nVol)
{
	if(nVol < 2) {
		return -1;
	}
	memset(szVol, base + 97, 1);
	memset(szVol + 1, 0, 2);

	return 0;
}

#ifdef UNICODE
#define GetVolumnByZeroBasedIndex  GetVolumnByZeroBasedIndexW
#else
#define GetVolumnByZeroBasedIndex  GetVolumnByZeroBasedIndexA
#endif // !UNICODE

#endif