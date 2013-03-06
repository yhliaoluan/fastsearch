#ifndef _STR_CMP_H_123123123123
#define _STR_CMP_H_123123123123

#include <Windows.h>

inline BOOL Str_StartWithA(const char *dest, const char *src)
{
	while(*src) {
		if(*(src++) != *(dest++)) {
			return FALSE;
		}
	}
	return TRUE;
}

inline BOOL Str_StartWithW(const WCHAR *dest, const WCHAR *src)
{
	while(*src) {
		if(*(src++) != *(dest++)) {
			return FALSE;
		}
	}
	return TRUE;
}

inline WCHAR Str_Reverse(WCHAR c)
{
	if(c >= L'a' && c <= L'z') {
		return c - 32;
	}
	if(c >= L'A' && c <= L'Z') {
		return c + 32;
	}
	return c;
}

inline BOOL StrI_StartWithW(const WCHAR *dest, const WCHAR *src)
{
	while(*src) {
		if(*src != *dest && *src != Str_Reverse(*dest)) {
			return FALSE;
		}
		src++;
		dest++;
	}
	return TRUE;
}

inline BOOL StrI_EndWithW(const WCHAR *dest, int destIndex, const WCHAR *src)
{
	int srcIndex = 0;
	if(destIndex < 0) {
		destIndex = wcslen(dest);
		if(destIndex <= 0) {
			return FALSE;
		}
	}
	while(*(src + srcIndex++));
	srcIndex -= 2;
	if(srcIndex < 0) {
		return TRUE;
	}
	while(srcIndex >= 0) {
		if(*(src + srcIndex) != *(dest + destIndex) &&
			*(src + srcIndex) != Str_Reverse(*(dest + destIndex))) {
			return FALSE;
		}
		srcIndex--;
		destIndex--;
	}
	return TRUE;
}

#ifdef UNICODE
#define Str_StartWith  Str_StartWithW
#else
#define Str_StartWith  Str_StartWithA
#endif // !UNICODE

#ifdef UNICODE
#define StrI_StartWith  StrI_StartWithW
//#else
//#define StrI_StartWith  StrI_StartWithW
#endif // !UNICODE

#ifdef UNICODE
#define StrI_EndWith  StrI_EndWithW
//#else
//#define StrI_StartWith  StrI_StartWithW
#endif // !UNICODE

#endif