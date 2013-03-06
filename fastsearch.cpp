#include "fastsearch.h"
#include "str_cmp.h"
#include "util.h"
#include "sqlite3.h"
#include <algorithm>
#include <map>
#include <vector>
#include <stack>
#include <Windows.h>

#pragma comment(lib, "sqlite3.lib")
using namespace tyrlib;

#define __END end_cleanup
#define ErrRet(s,n) (s)=(n);goto __END
#define VOLUMN_ROOT 0x5000000000005

typedef BOOL (*Str_Cmp)(const WCHAR *dest, int destIndex, const WCHAR *src);

inline BOOL Tyr_StrIStartWith(const WCHAR *dest, int destIndex, const WCHAR *src)
{
	return StrI_StartWith(dest, src);
}

inline BOOL Tyr_StrIEndWith(const WCHAR *dest, int destIndex, const WCHAR *src)
{
	return StrI_EndWith(dest, destIndex, src);
}

inline BOOL Tyr_StrIEquals(const WCHAR *dest, int destIndex, const WCHAR *src)
{
	return wcsicmp(dest, src) == 0;
}

typedef struct _st_THREAD_PARAM {
	FastSearch *instance;
	void *param;
} THREAD_PARAM;

typedef struct _st_MONITOR_PARAM {
	USN nextUSN;
	WCHAR szVol[MAX_PATH];
} MONITOR_PARAM;

FastSearch::FastSearch()
{
	char szMutex[MAX_PATH] = {0};
	GUID guid;
	CoCreateGuid(&guid);
	sprintf(szMutex, "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]);

	_mutex = CreateMutexA(NULL, FALSE, szMutex);
	_pThreads = new std::vector<HANDLE>();
	_pResults = new std::map<WCHAR, std::map<DWORDLONG, TYR_USN_RECORD *> *>();
}

inline void FastSearch::SafeDel(void *p)
{
	if(p!=NULL) {
		delete p;
	}
}

inline void FastSearch::SafeFree(void *p)
{
	if(p!=NULL) {
		free(p);
	}
}

FastSearch::~FastSearch()
{
	for(std::vector<HANDLE>::iterator vi = _pThreads->begin(); vi != _pThreads->end(); vi++) {
		if(*vi != NULL) {
			TerminateThread(*vi, 0);
			CloseHandle(*vi);
		}
	}
	printf("_pThreads closed.\n");
	SafeDel(_pThreads);

	for(std::map<WCHAR, std::map<DWORDLONG, TYR_USN_RECORD *>*>::iterator vi = _pResults->begin(); vi != _pResults->end(); vi++) {
		for(RecMI mi = vi->second->begin(); mi != vi->second->end(); mi++) {
//			printf("%d vol:%ls name:%ls [in]\n",
//				mi->second->frn,
//				mi->second->szVol,
//				mi->second->szFileName);
			free(mi->second->szFileName);
//			printf("[out]\n");
			free(mi->second);
		}
		SafeDel(vi->second);
	}
	printf("all records by frn deleted.\n");
	SafeDel(_pResults);
	printf("_pResults deleted.\n");
	if(_mutex != NULL) {
		CloseHandle(_mutex);
	}
	printf("_mutex deleted.\n");
}

void FastSearch::Clear(PRecMap p)
{
	p->clear();
}

inline TYR_USN_RECORD *FastSearch::Assemble(const USN_RECORD *usn_record,
											const WCHAR *szVol)
{
	TYR_USN_RECORD *rec = (TYR_USN_RECORD *)malloc(sizeof(TYR_USN_RECORD));
	rec->frn = usn_record->FileReferenceNumber;
	rec->pFrn = usn_record->ParentFileReferenceNumber;
	rec->dwAttribute = usn_record->FileAttributes;
	wcscpy(rec->szVol, szVol);
	rec->nFileNameLen = usn_record->FileNameLength;
	rec->szFileName = (WCHAR *)malloc(sizeof(WCHAR) * ((rec->nFileNameLen >> 1) + 1));
	memcpy(rec->szFileName, usn_record->FileName, rec->nFileNameLen);
	memset(rec->szFileName + (rec->nFileNameLen >> 1), 0, 2);
	return rec;
}

inline HANDLE FastSearch::CreateVolHandle(const WCHAR *szVol)
{
	WCHAR szVolFormat[MAX_PATH] = {0};
	swprintf(szVolFormat, L"\\\\.\\%s:", szVol);
	return CreateFile(
		szVolFormat,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
}

void FastSearch::PrintReason(DWORD dwReason)
{
	if(dwReason & USN_REASON_DATA_OVERWRITE) {
		printf("USN_REASON_DATA_OVERWRITE!\n");
	}
	if(dwReason & USN_REASON_DATA_EXTEND) {
		printf("USN_REASON_DATA_EXTEND!\n");
	}
	if(dwReason & USN_REASON_DATA_TRUNCATION) {
		printf("USN_REASON_DATA_TRUNCATION!\n");
	}
	if(dwReason & USN_REASON_NAMED_DATA_OVERWRITE) {
		printf("USN_REASON_NAMED_DATA_OVERWRITE\n");
	}
	if(dwReason & USN_REASON_NAMED_DATA_EXTEND) {
		printf("USN_REASON_NAMED_DATA_EXTEND\n");
	}
	if(dwReason & USN_REASON_NAMED_DATA_TRUNCATION) {
		printf("USN_REASON_NAMED_DATA_TRUNCATION\n");
	}
	if(dwReason & USN_REASON_FILE_CREATE) {
		printf("USN_REASON_FILE_CREATE\n");
	}
	if(dwReason & USN_REASON_FILE_DELETE) {
		printf("USN_REASON_FILE_DELETE\n");
	}
	if(dwReason & USN_REASON_EA_CHANGE) {
		printf("USN_REASON_EA_CHANGE\n");
	}
	if(dwReason & USN_REASON_SECURITY_CHANGE) {
		printf("USN_REASON_SECURITY_CHANGE\n");
	}
	if(dwReason & USN_REASON_RENAME_OLD_NAME) {
		printf("USN_REASON_RENAME_OLD_NAME\n");
	}
	if(dwReason & USN_REASON_RENAME_NEW_NAME) {
		printf("USN_REASON_RENAME_NEW_NAME\n");
	}
	if(dwReason & USN_REASON_INDEXABLE_CHANGE) {
		printf("USN_REASON_INDEXABLE_CHANGE\n");
	}
	if(dwReason & USN_REASON_BASIC_INFO_CHANGE) {
		printf("USN_REASON_BASIC_INFO_CHANGE\n");
	}
	if(dwReason & USN_REASON_HARD_LINK_CHANGE) {
		printf("USN_REASON_HARD_LINK_CHANGE\n");
	}
	if(dwReason & USN_REASON_COMPRESSION_CHANGE) {
		printf("USN_REASON_COMPRESSION_CHANGE\n");
	}
	if(dwReason & USN_REASON_ENCRYPTION_CHANGE) {
		printf("USN_REASON_ENCRYPTION_CHANGE\n");
	}
	if(dwReason & USN_REASON_OBJECT_ID_CHANGE) {
		printf("USN_REASON_OBJECT_ID_CHANGE\n");
	}
	if(dwReason & USN_REASON_REPARSE_POINT_CHANGE) {
		printf("USN_REASON_REPARSE_POINT_CHANGE\n");
	}
	if(dwReason & USN_REASON_STREAM_CHANGE) {
		printf("USN_REASON_STREAM_CHANGE\n");
	}
	if(dwReason & USN_REASON_TRANSACTED_CHANGE) {
		printf("USN_REASON_TRANSACTED_CHANGE\n");
	}
	if(dwReason & USN_REASON_INTEGRITY_CHANGE) {
		printf("USN_REASON_INTEGRITY_CHANGE\n");
	}
	if(dwReason & USN_REASON_CLOSE) {
		printf("USN_REASON_CLOSE\n");
	}
}

void FastSearch::PrintRecordInfo(const USN_RECORD *pRec)
{
	wprintf(L"File name: %.*s\n", pRec->FileNameLength >> 1, pRec->FileName);
	printf("USN: %lu\n", pRec->Usn);
	printf("FRN: %lu\n", pRec->FileReferenceNumber);
	printf("Parent FRN: %lu\n", pRec->ParentFileReferenceNumber);
	PrintReason(pRec->Reason);
	printf("\n");
}

int FastSearch::HandleChangedRecord(const USN_RECORD *pRec,
									const WCHAR *szVol)
{
	int err = 0;
	if(pRec == NULL) {
		ErrRet(err, -1);
	}
	if(pRec->Reason & USN_REASON_FILE_CREATE) {
		AddToMap(pRec, szVol);
	}
	else if(pRec->Reason & USN_REASON_FILE_DELETE) {
		std::map<DWORDLONG, TYR_USN_RECORD *> *pMap = (*_pResults)[*szVol];
		RecMI it = pMap->find(pRec->FileReferenceNumber);
		if(it == pMap->end()) {
			ErrRet(err, -2);
		}
		free(it->second->szFileName);
		free(it->second);
		pMap->erase(it);
	}
	else if(pRec->Reason & USN_REASON_RENAME_NEW_NAME) {
		std::map<DWORDLONG, TYR_USN_RECORD *> *pMap = (*_pResults)[*szVol];
		RecMI it = pMap->find(pRec->FileReferenceNumber);
		if(it == pMap->end()) {
			ErrRet(err, -2);
		}
		if(it->second->pFrn != pRec->ParentFileReferenceNumber) {
			it->second->pFrn = pRec->ParentFileReferenceNumber;
		}
		else {
			free(it->second->szFileName);
			it->second->nFileNameLen = pRec->FileNameLength;
			it->second->szFileName = (WCHAR *)malloc(sizeof(WCHAR) * ((it->second->nFileNameLen >> 1) + 1));
			memcpy(it->second->szFileName, pRec->FileName, it->second->nFileNameLen);
			memset(it->second->szFileName + (it->second->nFileNameLen >> 1), 0, 2);
		}
	}
__END:
//	PrintRecordInfo(pRec);
	return err;
}

int FastSearch::Monitor(USN *startUSN, const WCHAR *szVol)
{
	int err = 0;
	HANDLE hVol = CreateVolHandle(szVol);
	USN_JOURNAL_DATA journal_data = {0};
	READ_USN_JOURNAL_DATA read_usn_journal_data = {0};
	const int nBufferSize = 1024 * 1024;
	USN_RECORD *pRecord = NULL;
	BYTE *buffer = (BYTE *)malloc(sizeof(BYTE) * nBufferSize);
	DWORD dwRetBytes = 0;
	if(!DeviceIoControl(hVol,
		FSCTL_QUERY_USN_JOURNAL,
		NULL,
		0,
		&journal_data,
		sizeof(journal_data),
		&dwRetBytes,
		NULL)) {
			printf("DeviceIoControl FSCTL_QUERY_USN_JOURNAL failed. %d\n", GetLastError());
			err = -1;
			goto __END;
	}
	read_usn_journal_data.UsnJournalID = journal_data.UsnJournalID;
	read_usn_journal_data.StartUsn = *startUSN;
	read_usn_journal_data.ReasonMask = USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE;
	read_usn_journal_data.ReturnOnlyOnClose = 1;
	read_usn_journal_data.Timeout = (DWORDLONG)-20000000;
	read_usn_journal_data.BytesToWaitFor = 1024 * 16;
	for(;;) {
		if(!DeviceIoControl(hVol,
			FSCTL_READ_USN_JOURNAL,
			&read_usn_journal_data,
			sizeof(read_usn_journal_data),
			buffer,
			nBufferSize,
			&dwRetBytes,
			NULL)) {
				printf("DeviceIoControl FSCTL_READ_USN_JOURNAL failed. %d\n", GetLastError());
				err = -1;
				break;
		}
		Lock(_mutex);
		dwRetBytes = dwRetBytes - sizeof(USN);
		pRecord = (USN_RECORD *)((USN *)buffer + 1);
		while(dwRetBytes > 0) {
			if(err = HandleChangedRecord(pRecord, szVol)) {
				printf("err: %d\n", err);
				PrintRecordInfo(pRecord);
			}
			dwRetBytes -= pRecord->RecordLength;
			pRecord = (USN_RECORD *)((BYTE *)pRecord + pRecord->RecordLength);
		}
		read_usn_journal_data.StartUsn = *((USN *)buffer);
		UnLock(_mutex);
	}
__END:
	if(hVol != NULL) {
		CloseHandle(hVol);
	}
	SafeFree(buffer);
	return err;
}

inline int FastSearch::AddToMap(const USN_RECORD *pRec, const WCHAR *szVol)
{
	std::map<DWORDLONG, TYR_USN_RECORD *> * pMap;
	std::map<WCHAR, std::map<DWORDLONG, TYR_USN_RECORD *> *>::iterator vi;
	vi = _pResults->find(*szVol);
	if(vi == _pResults->end()) {
		pMap = new std::map<DWORDLONG, TYR_USN_RECORD *>();
		(*_pResults)[*szVol] = pMap;
	}
	else {
		pMap = vi->second;
	}
	RecMI mi = pMap->find(pRec->FileReferenceNumber);
	if(mi != pMap->end()) {
		TYR_USN_RECORD *record = Assemble(pRec, szVol);
		wprintf(L"old name: %ls  old vol: %ls\n", mi->second->szFileName, mi->second->szVol);
		wprintf(L"new name: %ls  new vol: %ls\n", record->szFileName, record->szVol);
		free(record->szFileName);
		delete record;
		free(mi->second->szFileName);
		delete mi->second;
	}
	(*pMap)[pRec->FileReferenceNumber] = Assemble(pRec, szVol);
	return 0;
}

int FastSearch::Traverse(const WCHAR *szVol, USN *nextUSN)
{
	int err = 0;
	HANDLE hVol = CreateVolHandle(szVol);
	MFT_ENUM_DATA mft_enum_data = {0};
	USN_JOURNAL_DATA journal_data = {0};
	USN_RECORD *pRecord = NULL;
	const int nBufferSize = 1024 * 1024;
	BYTE *buffer = (BYTE *)malloc(sizeof(BYTE) * nBufferSize);
	DWORD dwRetBytes = 0;
	if(!DeviceIoControl(hVol,
		FSCTL_QUERY_USN_JOURNAL,
		NULL,
		0,
		&journal_data,
		sizeof(journal_data),
		&dwRetBytes,
		NULL)) {
			printf("DeviceIoControl FSCTL_QUERY_USN_JOURNAL failed. %d\n", GetLastError());
			ErrRet(err,-1);
	}
	*nextUSN = mft_enum_data.HighUsn = journal_data.NextUsn;
	for(;;) {
		if(!DeviceIoControl(hVol,
			FSCTL_ENUM_USN_DATA,
			&mft_enum_data,
			sizeof(mft_enum_data),
			buffer,
			nBufferSize,
			&dwRetBytes,
			NULL)) {
				printf("DeviceIoControl FSCTL_ENUM_USN_DATA failed. %d\n", GetLastError());
				ErrRet(err,-1);
		}
		dwRetBytes = dwRetBytes - sizeof(DWORDLONG);
		pRecord = (USN_RECORD *)((DWORDLONG *)buffer + 1);
		while(dwRetBytes > 0) {
			if(pRecord->FileNameLength > 0) {
				AddToMap(pRecord, szVol);
			}
			dwRetBytes -= pRecord->RecordLength;
			pRecord = (USN_RECORD *)((BYTE *)pRecord + pRecord->RecordLength);
		}
		mft_enum_data.StartFileReferenceNumber = *((DWORDLONG *)buffer);
	}
__END:
	if(hVol != NULL) {
		CloseHandle(hVol);
	}
	SafeFree(buffer);
	return err;
}

int FastSearch::Search(IN WCHAR *szWord, OUT std::vector<TYR_SEARCH_RESULT *> *pVector)
{
	int err = 0;
	WCHAR szFullPath[1024] = {0};
	Str_Cmp cmp = Tyr_StrIEquals;
	if(StrI_StartWith(szWord, L"*")) {
		szWord++;
		cmp = Tyr_StrIEndWith;
	}

	Lock(_mutex);
	for(std::map<WCHAR, std::map<DWORDLONG, TYR_USN_RECORD *>*>::iterator vi = _pResults->begin(); vi != _pResults->end(); vi++) {
		for(RecMI mi = vi->second->begin(); mi != vi->second->end(); mi++) {
			if(cmp(mi->second->szFileName, (mi->second->nFileNameLen >> 1) - 1, szWord)) {
				size_t nPath = 1024;
				GetFullPath(mi->second->frn, vi->first, szFullPath, &nPath);
				TYR_SEARCH_RESULT *pRes = (TYR_SEARCH_RESULT *)malloc(sizeof(TYR_SEARCH_RESULT));
				pRes->nFolderNameLen = nPath;
				pRes->nFileNameLen = (mi->second->nFileNameLen >> 1);
				pRes->dwAttribute = mi->second->dwAttribute;
				pRes->szFileName = (WCHAR *)malloc(sizeof(WCHAR) * (pRes->nFileNameLen + 1));
				wcsncpy(pRes->szFileName, mi->second->szFileName, pRes->nFileNameLen);
				memset(pRes->szFileName + pRes->nFileNameLen, 0, 2);
				pRes->szFolderName = (WCHAR *)malloc(sizeof(WCHAR) * (pRes->nFolderNameLen + 1 + 3));
				wcscpy(pRes->szFolderName, mi->second->szVol);
				wcscpy(pRes->szFolderName + 1, L":/");
				wcsncpy(pRes->szFolderName + 3, szFullPath, pRes->nFolderNameLen);
				memset(pRes->szFolderName + pRes->nFolderNameLen + 3, 0, 2);
				pVector->push_back(pRes);
			}
		}
	}
	UnLock(_mutex);
	return err;
}

int FastSearch::GetFullPath(IN DWORDLONG frn,
							IN WCHAR vol,
							OUT WCHAR *szFullPath,
							IN OUT size_t *nFullPathLen)
{
	int err = 0;
	std::stack<TYR_USN_RECORD *> stackName;
	std::map<DWORDLONG, TYR_USN_RECORD *> *pMap = (*_pResults)[vol];
	TYR_USN_RECORD *pRec = (*pMap)[frn];
	size_t len = 0;
	while(pRec->pFrn != VOLUMN_ROOT) {
		pRec = (*pMap)[pRec->pFrn];
		stackName.push(pRec);
	}
	while(!stackName.empty()) {
		pRec = stackName.top();
		if((len + ((pRec->nFileNameLen >> 1) + 1)) > *nFullPathLen) {
			ErrRet(err,-1);
		}
		wcscpy(szFullPath + len, pRec->szFileName);
		len += (pRec->nFileNameLen >> 1);
		wcscpy(szFullPath + len, L"/");
		len += 1;
		stackName.pop();
	}
	*nFullPathLen = len;
__END:
	return err;
}

DWORD __stdcall TyrLib_ThreadMonitor(void *p)
{
	THREAD_PARAM *pParam = (THREAD_PARAM *)p;
	MONITOR_PARAM *pMonitorParam = (MONITOR_PARAM *)pParam->param;
	wprintf(L"Begin monitor %s\n", pMonitorParam->szVol);
	pParam->instance->Monitor(&pMonitorParam->nextUSN, pMonitorParam->szVol);
	free(pMonitorParam);
	free(p);
	return 0;
}

int FastSearch::TraverseAndMonitorAll()
{
	int err = 0;
	int i = 0;
	int c = 1;
	WCHAR szFSName[MAX_PATH] = {0};
	WCHAR szVol[2] = {0};
	WCHAR szVolSlash[MAX_PATH] = {0};
	DWORD driveType;
	DWORD dwDrives = GetLogicalDrives();
	for(; i < 26; i++) {
		if((dwDrives & c) == c) {
			GetVolumnByZeroBasedIndex(i, szVol, 2);
			wsprintf(szVolSlash, L"%s:\\", szVol);
			driveType = GetDriveType(szVolSlash);
			if(driveType != DRIVE_FIXED) {
				continue;
			}
			GetVolumeInformation(szVolSlash, NULL,
				MAX_PATH, NULL, 
				NULL, NULL,
				szFSName, MAX_PATH);
			if(wcscmp(szFSName, L"NTFS") == 0) {
				USN nextUSN;
				Traverse(szVol, &nextUSN);
				MONITOR_PARAM *param = (MONITOR_PARAM *)malloc(sizeof(MONITOR_PARAM));
				param->nextUSN = nextUSN;
				wcscpy(param->szVol, szVol);
				THREAD_PARAM *pParam = (THREAD_PARAM *)malloc(sizeof(THREAD_PARAM));
				pParam->instance = this;
				pParam->param = param;
				HANDLE hThread = CreateThread(NULL,
					0,
					TyrLib_ThreadMonitor,
					pParam,
					0,
					NULL);
				_pThreads->push_back(hThread);
			}
		}
		c <<= 1;
	}
__END:
	return err;
}

int FastSearch::ClearResults(std::vector<TYR_SEARCH_RESULT *> *pResults)
{
	int err = 0;
	std::vector<TYR_SEARCH_RESULT *>::iterator vi = pResults->begin();
	for(; vi != pResults->end(); vi++) {
		free((*vi)->szFileName);
		free((*vi)->szFolderName);
		free(*vi);
	}
	pResults->clear();
__END:
	return err;
}

int FastSearch::Lock(HANDLE h)
{
	int err = 0;
	DWORD dwWaitRst;
	if(h == NULL) {
		ErrRet(err,-1);
	}
	dwWaitRst = WaitForSingleObject(h, INFINITE);
	switch(dwWaitRst) {
	case WAIT_OBJECT_0:
		break;
	default:
		ErrRet(err,-2);
	}
__END:
	return err;
}

int FastSearch::UnLock(HANDLE h)
{
	int err = 0;
	if(!ReleaseMutex(h)) {
		ErrRet(err,-1);
	}
__END:
	return err;
}