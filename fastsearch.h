
#ifndef _TYR_FASTSEARCH_H_
#define _TYR_FASTSEARCH_H_

#include <stdio.h>
#include <Windows.h>
#include <map>
#include <vector>

namespace tyrlib
{
	typedef struct _st_TYR_USN_RECORD {
		WORD nFileNameLen;
		DWORDLONG frn;
		DWORDLONG pFrn;
		DWORD dwAttribute;
		WCHAR szVol[2];
		WCHAR *szFileName;
	} TYR_USN_RECORD;

	typedef struct _st_TYR_SEARCH_RESULT {
		WORD nFileNameLen;
		WORD nFolderNameLen;
		WCHAR *szFileName;
		WCHAR *szFolderName;
		DWORD dwAttribute;
	} TYR_SEARCH_RESULT;

	typedef std::map<DWORDLONG, TYR_USN_RECORD *>::iterator RecMI;
	typedef std::map<DWORDLONG, TYR_USN_RECORD *> RecMap, *PRecMap;

	class FastSearch
	{
	public:
		FastSearch();
		virtual ~FastSearch();
		
		int Traverse(const WCHAR *szVol, USN *nextUSN);
		int Monitor(USN *startUSN, const WCHAR *szVol);
		int Search(IN WCHAR *szWord, OUT std::vector<TYR_SEARCH_RESULT *> *pVector);
		int TraverseAndMonitorAll();
		int ClearResults(std::vector<TYR_SEARCH_RESULT *> *pResults);

	private:
//		PRecMap _pMapByFRN;
		std::map<WCHAR, std::map<DWORDLONG, TYR_USN_RECORD *>*> *_pResults;
		HANDLE _mutex;
		std::vector<HANDLE> *_pThreads;

	private:
		void Clear(PRecMap p);
		TYR_USN_RECORD *Assemble(const USN_RECORD *usn_record, const WCHAR *szVol);
		HANDLE CreateVolHandle(const WCHAR *szVol);
		void PrintReason(DWORD dwReason);
		void PrintRecordInfo(const USN_RECORD *pRec);
		void SafeDel(void *p);
		void SafeFree(void *p);
		int HandleChangedRecord(const USN_RECORD *pRec, const WCHAR *szVol);
		int AddToMap(const USN_RECORD *pRec, const WCHAR *szVol);
		int GetFullPath(IN DWORDLONG frn, IN WCHAR vol, OUT WCHAR *szFullPath, IN OUT size_t *nFullPathLen);
		int Lock(HANDLE h);
		int UnLock(HANDLE h);

	private:
		FastSearch(const FastSearch&);
		FastSearch &operator=(const FastSearch&);
	};
};

#endif