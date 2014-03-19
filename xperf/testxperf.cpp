// xperf.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <Shlwapi.h>

#include "provider.h"
#include "controller.h"
#include "consumer.h"
#include "ETWUlt.h"

#pragma comment(lib, "Shlwapi.lib")
//#include <strsafe.h>

DWORD WINAPI providerRoutine(void* lparam)
{
	CProvider::RegisterProviderGuid();
	CProvider::TraceSpecificEvent(1);
	Sleep(200);
	CProvider::TraceSpecificEvent(2);
	return 0;
}


#define		REGEDIT_THUNDER_SUB_KEY						L"SOFTWARE\\Thunder Network\\ThunderOem\\thunder_backwnd"
#define		REGEDIT_THUNDER_KEY_VALUE_PATH				L"Path"
#define		REGEDIT_THUNDER_KEY_VALUE_VERSION			L"Version"
#define		REGEDIT_THUNDER_KEY_VALUE_INTASLLDIR		L"instdir"

BOOL GetThunderInstallDir(std::wstring& wszInstallDir)
{
	const size_t cdwBufferSize = 512;
	wchar_t szBuffer[cdwBufferSize] = {0};
	DWORD dwBufferSize = cdwBufferSize;
	DWORD dwType = (DWORD)-1;

	if (ERROR_SUCCESS == SHGetValue(HKEY_LOCAL_MACHINE, REGEDIT_THUNDER_SUB_KEY, REGEDIT_THUNDER_KEY_VALUE_INTASLLDIR, &dwType, szBuffer, &dwBufferSize))
	{
		if (wcslen(szBuffer) > 0)
		{
			wszInstallDir = szBuffer;
			if (wszInstallDir[wszInstallDir.length()-1] != L'\\')
			{
				wszInstallDir += L"\\program\\thunder.exe";
			}
			return TRUE;
		}

		return FALSE;
	}

	return FALSE;
}


int _tmain(int argc, _TCHAR* argv[])
{
// 	CController *pCtrl = new CController();
// 	std::wstring temp;
// 
// 

// 	
// 	pCtrl->CtrStartTrace(temp);
// 	DWORD threadId = 0;
//  	HANDLE hThread = CreateThread(0,0,providerRoutine,0,0,&threadId);
// 	pCtrl->CtrParseTrace();


	std::wstring programPath;
	GetThunderInstallDir(programPath);

	CEtwUlt<CController,CConsumerWrap<CConsumer>> Ult;
	if(!Ult.run(programPath))
	{
		wprintf(L"Run Failed");
	}

	system("pause");

// 	CConsumerWrap<CConsumer>* p = CConsumerWrap<CConsumer>::GetInstance();
// 	p->ParseTraceFile((LPWSTR)(L"D:\\test.etl"));
// 	system("pause");
// 	return 0;


}

