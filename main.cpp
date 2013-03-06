#include <stdio.h>
#include <Windows.h>
#include <vector>
#include <map>
#include <stack>
#include <algorithm>
#include "sqlite3.h"
#include "fastsearch.h"
#include "str_cmp.h"

int main()
{
	tyrlib::FastSearch *fs = new tyrlib::FastSearch();
	WCHAR szWord[MAX_PATH] = {0};
	std::vector<tyrlib::TYR_SEARCH_RESULT *> vector;

	fs->TraverseAndMonitorAll();
	
	printf("Please input a file name:\n");
	wscanf(L"%ls", szWord);
	while(wcscmp(szWord, L"-1") != 0) {
		fs->Search(szWord, &vector);
		for(std::vector<tyrlib::TYR_SEARCH_RESULT *>::iterator vi = vector.begin();
			vi != vector.end(); vi++) {
				printf("Name: %ls \n", (*vi)->szFileName);
				printf("Folder: %ls \n", (*vi)->szFolderName);
				printf("Attribute: %d \n\n", (*vi)->dwAttribute);
		}
		fs->ClearResults(&vector);
		printf("Please input a file name:\n");
		wscanf(L"%ls", szWord);
	}

	delete fs;

	return 0;
}

