
#include "stdafx.h"
#include<algorithm>
#include "consumer.h"
#include "version.h"
#include<string>
#include <in6addr.h>
#include <dbghelp.h>
#include <Psapi.h>
#include "provider.h"
#pragma comment(lib, "dbghelp.lib")

#pragma comment(lib, "comsupp.lib")  // For _bstr_t class
#pragma comment(lib, "ws2_32.lib")  // For ntohs function

#pragma comment(lib, "comsupp.lib")  // For _bstr_t class
#pragma comment(lib, "psapi.lib")

IWbemServices* g_pServices = NULL;

#define STACK_MATCH_COUNT 4

/*-------------------------------------华丽的分割线-----------------------------------------------*/

CConsumer::CConsumer() : m_beginTimeStamp(0), m_endTimeStamp(0), m_totalSampleCount(0), m_processSampleCount(0), m_processId(0), m_processHandle(NULL), m_stackMatchCount(0),m_isContinueTrace(TRUE)
{
	m_totalReadTime = 0;
	m_totalReadBytes = 0;
	m_timeStamp = 0;
	m_startTimeUsed.QuadPart = 0;
	m_processStartSamp.QuadPart = 0;
	m_preStackWalkStamp = 0;
	if(GetSystemBits() == 32 )
	{
		MOF_POINTERSIZE = 4;
	}
}

BOOL CConsumer::ConsumerProcessTrace(TRACEHANDLE hTrace, DWORD processId, LPWSTR logFilePath)
{


// 	HRESULT hr = ConnectToETWNameSpace(_bstr_t(L"root\\wmi"));
// 	if(FAILED(hr))
// 	{
// 		wprintf(L"ConnectoETWNameSpace failed with 0x%x\r\n", hr);	
// 	}
	m_logFilePath = logFilePath;
	m_processId = processId;

	SymSetOptions(SYMOPT_DEBUG);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE, m_processId);
	if(hProcess == NULL)
	{
		wprintf(L"OpenProcess Failed with %lu\r\n", GetLastError());
	}
	else
	{

		HMODULE hMod[1024];
		DWORD	cbNeeded;
		TCHAR	szModName[MAX_PATH] = {0};
		std::string pdbSerchPath = "\\\\192.168.14.181\\public\\symbols\\";
		std::string finalSearchPath = "d:\\symbolslocal";
		if(EnumProcessModules(hProcess, hMod, sizeof(hMod), &cbNeeded))
		{
			for(int i = 0; i < cbNeeded / sizeof(HMODULE); ++i)
			{
				pdbSerchPath = "\\\\192.168.14.181\\public\\symbols\\";
				ZeroMemory(szModName, sizeof(szModName));
				if(GetModuleFileNameEx(hProcess, hMod[i], szModName, sizeof(szModName)))
				{
					CFileVersion fileVer;
					if(fileVer.Open(szModName))
					{
						CString strVer = fileVer.GetFixedProductVersion();
						std::wstring modName = szModName;
						DWORD index = modName.rfind(L'\\');
						DWORD suffixIndex = modName.rfind(L'.');
						if(index)
						{
							modName = modName.substr(index+1,suffixIndex - index -1);
						}
						modName += L"\\";
						modName += strVer.GetBuffer();
						strVer.ReleaseBuffer();

						char modPdbPath[MAX_PATH] = {0};
						WideCharToMultiByte(CP_ACP,0, modName.c_str(), -1, modPdbPath, MAX_PATH, NULL, FALSE);

						pdbSerchPath += modPdbPath;
						if(PathFileExistsA(pdbSerchPath.c_str()))
						{
							finalSearchPath = finalSearchPath + ";" + pdbSerchPath;
						}

					}
				}
			}
			finalSearchPath = finalSearchPath + ";" + "\\\\192.168.14.181\\public\\symbols\\Thunder\\7.9.19.4736";
			BOOL bRet = SymInitialize ( 
				hProcess, // Process handle
				finalSearchPath.c_str(),       // user-defined search path -> use default 
				TRUE                 // load symbols for modules in the current process 
				); 
			m_processHandle = hProcess;
		}

		//std::string pdbSerchPath = "\\\\192.168.14.181\\public\\symbols\\Thunder\\7.9.19.4736;D:\\develop\\thunder\\pdb\\Release";		
	}
	

	ULONG status = ProcessTrace(&hTrace, 1, 0, 0);
	if(ERROR_SUCCESS != status && ERROR_CANCELLED != status)
	{
		wprintf(L"ProcessTrace failed with %u\r\n", status);
	}
	else
	{
		OutputResult();
	}
	//CoUninitialize();
	return TRUE;
}

ULONG WINAPI CConsumer::ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer)
{
	return TRUE;
}

void WINAPI CConsumer::ProcessEvent(PEVENT_TRACE pEvent)
{
	WCHAR ClassGuid[50];
	IWbemClassObject *pEventCategoryClass = NULL;
	IWbemClassObject *pEventClass = NULL;
	PBYTE pEventData = NULL;
	PBYTE pEndOfEventData = NULL;
	PROPERTY_LIST *pProperties = NULL;
	DWORD PropertyCount = 0;
	LONG *pProPertyIndex = NULL;
	ULONGLONG TimeStamp = 0;
	SYSTEMTIME st;
	SYSTEMTIME stLocal;
	FILETIME ft;
	ULONG diskReadTransfer = 0;
	UINT64 highResResponseTime = 0; 
	DWORD threadId = 0;

	if(!m_isContinueTrace && !IsEqualGUID(pEvent->Header.Guid, FileIoGuid))
		return ;

	UINT32 instrumentPointer = 0;

	if(IsEqualGUID(pEvent->Header.Guid, EventTraceGuid) && EVENT_TRACE_TYPE_INFO == pEvent->Header.Class.Type )
	{
		;	// Skip this Event.
	}

	else
	{
		StringFromGUID2(pEvent->Header.Guid, ClassGuid, sizeof(ClassGuid));
		TimeStamp = pEvent->Header.TimeStamp.QuadPart;

		pEventData = (PBYTE) pEvent->MofData;
		UCHAR eventType = pEvent->Header.Class.Type;

		if(IsEqualGUID(pEvent->Header.Guid,ProcessGuid) && pEvent->MofLength > 0)
		{
			if(eventType == EVENT_TRACE_TYPE_START)
			{
				UINT32 processID;
				CopyMemory(&processID, pEventData+MOF_POINTERSIZE, sizeof(UINT32));
				if(processID == m_processId)
					m_processStartSamp.QuadPart = TimeStamp;
			}
		}

		if(IsEqualGUID(pEvent->Header.Guid, PageFaultGuid) && pEvent->MofData > 0)
		{
			if(32 == eventType)				// hard faults
			{
				CopyMemory(&threadId, pEventData+16+2*MOF_POINTERSIZE, sizeof(UINT32));
				for(std::vector<DWORD>::iterator ite = m_vecThreadId.begin(); ite != m_vecThreadId.end(); ++ite)
				{
					if(*ite == threadId )
					{
						UINT64 readOffset, vtAddr, fileObject,initTimeStamp;
						UINT32 byteCount = 0;
						CopyMemory(&initTimeStamp, pEventData, 8);
						CopyMemory(&readOffset, pEventData+8, 8);
						CopyMemory(&vtAddr, pEventData + 16, MOF_POINTERSIZE);
						CopyMemory(&fileObject, pEventData +16+MOF_POINTERSIZE, MOF_POINTERSIZE);
						CopyMemory(&byteCount, pEventData+20+2*MOF_POINTERSIZE, sizeof(UINT32));
						CHardFaults hardFaultsTemp;
						hardFaultsTemp.initTime = initTimeStamp;
						hardFaultsTemp.fileObj = fileObject;
						hardFaultsTemp.fileOffset = readOffset;
						hardFaultsTemp.vtAddress = vtAddr;
						hardFaultsTemp.byteCount = byteCount;

						MAP_FILEOBJ_ITE mapIte = m_mapFileObjectToFileName.begin();
						for(; mapIte != m_mapFileObjectToFileName.end() ; ++mapIte)
						{
							if(mapIte->first == hardFaultsTemp.fileObj)
								break;
						}
						if(mapIte == m_mapFileObjectToFileName.end())
						{
							m_vecHardFaults.push_back(hardFaultsTemp);
						}
						else
						{
							VEC_FILEFAULTS_ITE iteFaults;
							for(iteFaults = m_vecFileFaults.begin(); iteFaults != m_vecFileFaults.end(); ++iteFaults)
							{
								if(wcscmp(iteFaults->fileName.c_str(), mapIte->second.c_str()) == 0 )
									break;
							}
							if(iteFaults != m_vecFileFaults.end())
							{
								iteFaults->faultCount += 1;
								iteFaults->readSize += hardFaultsTemp.byteCount;
								iteFaults->vec_Fault.push_back(hardFaultsTemp);
							}
							else
							{
								CFileHardFaults fileHardFaults;
								fileHardFaults.fileObj = mapIte->first;
								fileHardFaults.faultCount = 1;
								fileHardFaults.readSize = hardFaultsTemp.byteCount;
								fileHardFaults.fileName = mapIte->second;
								fileHardFaults.vec_Fault.push_back(hardFaultsTemp);
								m_vecFileFaults.push_back(fileHardFaults);
							}
						}
						break;
					}
				}
			}
		}

		if(IsEqualGUID(pEvent->Header.Guid, StackWalkGuid)  && pEvent->MofLength > 0 )
		{
			int processId = 0;
			CopyMemory(&processId, pEventData + 8, 4);
			if(processId == m_processId)
			{
				BOOL bRet = FALSE;
				UINT64 TimeStamp=0;		// 具体事件触发时候的时间戳，
				CopyMemory(&TimeStamp, pEventData, sizeof(UINT64));
				if(m_preStackWalkStamp == 0)
				{
					m_preStackWalkStamp= TimeStamp;
					return;
				}

				int stackFrameCount = (pEvent->MofLength - 16)/MOF_POINTERSIZE;

				UINT64 stack1 = 0;
				CopyMemory(&stack1, pEventData+16, MOF_POINTERSIZE);

				if(INT64(stack1) < 0 )
					return ;
				std::vector<std::string> vecTemp;
				for(int i=0; i <  stackFrameCount; ++i)
				{		
					std::string sym;
					UINT64 stackEnd = 0;
					CopyMemory(&stackEnd, pEventData+16+i*MOF_POINTERSIZE, MOF_POINTERSIZE);
					DWORD64 dwDisp64;
					BYTE buffer[4096];
					SYMBOL_INFO* sym_info = (SYMBOL_INFO*)buffer;
					sym_info->SizeOfStruct = sizeof(SYMBOL_INFO);
					sym_info->MaxNameLen = 4096-sizeof(SYMBOL_INFO)-1;
					BOOL bGetSym = SymFromAddr(m_processHandle,stackEnd,&dwDisp64, sym_info);

					IMAGEHLP_MODULE64 mi;
					memset(&mi, 0, sizeof(IMAGEHLP_MODULE64));
					mi.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
					BOOL bGetModuleInfo = SymGetModuleInfo64(m_processHandle, stackEnd, &mi);   

					if(bGetModuleInfo)
						sym = (std::string)(mi.ModuleName) + "!";
					if(bGetSym)
						sym = sym + sym_info->Name;
					char stackAddress[64] = {0};
					_i64toa_s(stackEnd, stackAddress,64, 16);
					sym += "(0x";
					sym += stackAddress;
					sym += ")";
					vecTemp.push_back(sym);
				}

				SAMPLE_STACK sampleStack;
				sampleStack.timeStamp = TimeStamp;
				sampleStack.timeInterval = TimeStamp - m_preStackWalkStamp;
				sampleStack.vecStack = vecTemp;
				m_vecSampleStack.push_back(sampleStack);
				m_preStackWalkStamp = TimeStamp;
			}
			
		}

		if(IsEqualGUID(pEvent->Header.Guid, FileIoGuid) && pEvent->MofLength > 0)
		{
			UINT64 fileObjectPtr = 0;
			wchar_t fileName[MAX_PATH] = {0};
			
			if( 0 == eventType || 32 == eventType || 35 == eventType || 36 == eventType)
			{
				int lenth = wcslen((wchar_t*)(pEventData+MOF_POINTERSIZE));
				CopyMemory(fileName, pEventData+MOF_POINTERSIZE, lenth*sizeof(wchar_t));
				
				CopyMemory(&fileObjectPtr, pEventData, MOF_POINTERSIZE);

				m_mapFileObjectToFileName[fileObjectPtr] = fileName;
			}

//  			if(64 == eventType)		//创建文件
//  			{
//  				int lenth = wcslen((wchar_t*) (pEventData + 12 + MOF_POINTERSIZE*3));
//  				CopyMemory(fileName, pEventData + 12 + MOF_POINTERSIZE*3, lenth*sizeof(wchar_t));
//  				CopyMemory(&fileObjectPtr, pEventData + 2*MOF_POINTERSIZE, MOF_POINTERSIZE);
// 				m_mapFileCreate[fileObjectPtr] = fileName;
//  			}
//  
//  			if(67 == eventType || 68 == eventType)		//文件读写
//  			{
//  				UINT64 fileCreateObj;
//  				CopyMemory(&fileCreateObj, pEventData + 8 + 2*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				CopyMemory(&fileObjectPtr, pEventData + 8 + 3*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				MAP_FILEOBJ_ITE iteCreate = m_mapFileCreate.find(fileCreateObj);
//  				if(iteCreate != m_mapFileCreate.end())
//  				{
//  					m_mapFileObjectToFileName[fileObjectPtr] = iteCreate->second;
//  				}
//  				
//  			}
//  
//  			if(65 == eventType || 66 == eventType || 73 == eventType)
//  			{
//  				UINT64 fileCreateObj;
//  				CopyMemory(&fileCreateObj, pEventData + 2*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				CopyMemory(&fileObjectPtr, pEventData + 3*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				MAP_FILEOBJ_ITE iteCreate = m_mapFileCreate.find(fileCreateObj);
//  				if(iteCreate != m_mapFileCreate.end())
//  				{
//  					m_mapFileObjectToFileName[fileObjectPtr] = iteCreate->second;
//  				}
//  			}
//  
//  			if(69 == eventType || 70 == eventType || 71 == eventType || 74 == eventType || 75 == eventType)
//  			{
//  				UINT64 fileCreateObj;
//  				CopyMemory(&fileCreateObj, pEventData + 2*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				CopyMemory(&fileObjectPtr, pEventData + 3*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				MAP_FILEOBJ_ITE iteCreate = m_mapFileCreate.find(fileCreateObj);
//  				if(iteCreate != m_mapFileCreate.end())
//  				{
//  					m_mapFileObjectToFileName[fileObjectPtr] = iteCreate->second;
//  				}
//  			}
//  
//  			if(72 == eventType || 77 == eventType)
//  			{
//  // 				int lenth = wcslen((wchar_t*) (pEventData+8 + 5*MOF_POINTERSIZE));
//  // 				CopyMemory(fileName, pEventData+8 + 5*MOF_POINTERSIZE, lenth*sizeof(wchar_t));
//  				UINT64 fileCreateObj;
//  				CopyMemory(&fileCreateObj, pEventData+2*MOF_POINTERSIZE, MOF_POINTERSIZE);
//  				CopyMemory(&fileObjectPtr,pEventData+3*MOF_POINTERSIZE,MOF_POINTERSIZE);
//  				MAP_FILEOBJ_ITE iteCreate = m_mapFileCreate.find(fileCreateObj);
//  				if(iteCreate != m_mapFileCreate.end())
//  				{
//  					m_mapFileObjectToFileName[fileObjectPtr] = iteCreate->second;
//  				}
//  			}
		}

		if(IsEqualGUID(pEvent->Header.Guid,MyCategoryGuid))
		{
			if(THUNDER_PROVIDER_TYPE_END == pEvent->Header.Class.Type)
			{
				m_isContinueTrace = FALSE;
				m_startTimeUsed.QuadPart = TimeStamp - m_processStartSamp.QuadPart;
			}
		}

		if(IsEqualGUID(pEvent->Header.Guid, ThreadGuid) && pEvent->MofLength > 0)
		{
			DWORD processID = 0;
			CopyMemory(&processID, pEventData, 4);
			if(EVENT_TRACE_TYPE_START == pEvent->Header.Class.Type /*|| 3 == pEvent->Header.Class.Type*/)
			{
				if(m_processId == processID )
				{
					CopyMemory(&threadId, pEventData + 4, 4);
					m_vecThreadId.push_back(threadId);
				}
			}
			if(EVENT_TRACE_TYPE_END == pEvent->Header.Class.Type)
			{
				if(m_processId == processID)
				{
					CopyMemory(&threadId, pEventData + 4, 4);
					for(std::vector<DWORD>::iterator ite = m_vecThreadId.begin(); ite != m_vecThreadId.end(); ++ite)
					{
						if(*ite == threadId)
						{
							m_vecThreadId.erase(ite);
							break;
						}
					}
				}
			}
		}

		if(IsEqualGUID(pEvent->Header.Guid, PerfInfoGuid) && pEvent->MofLength > 0)
		{
			if(m_processStartSamp.QuadPart == 0)		// 进程还没开始
				return;
			if(46 == pEvent->Header.Class.Type)			// sample profile
			{
				if(m_beginTimeStamp == 0)
					m_beginTimeStamp = TimeStamp;
				m_endTimeStamp = TimeStamp;

				m_totalSampleCount += 1;

				DWORD perfThreadId = -1;
				CopyMemory(&perfThreadId, pEventData+8, 4);

				for(std::vector<DWORD>::iterator ite = m_vecThreadId.begin(); ite != m_vecThreadId.end(); ++ite)
				{
					if(*ite == perfThreadId )
					{
						m_processSampleCount += 1;
						break;
					}
				}
				 
			}

		}

		if(IsEqualGUID(pEvent->Header.Guid, DiskIoGuid ) && pEvent->MofLength > 0)
		{
			if((EVENT_TRACE_TYPE_IO_READ == pEvent->Header.Class.Type || EVENT_TRACE_TYPE_IO_WRITE == pEvent->Header.Class.Type) && pEvent->Header.ProcessId == m_processId)
			{
// 				pEventCategoryClass = GetEventCategoryClass(_bstr_t(ClassGuid), pEvent->Header.Version);
// 				if(pEventCategoryClass)
// 				{
// 					pEventClass = GetEventClass(pEventCategoryClass, pEvent->Header.Class.Type);
// 					pEventCategoryClass->Release();
// 					pEventCategoryClass = NULL;
// 					if(pEventClass)
// 					{
// 						if(TRUE == GetPropertyList(pEventClass, &pProperties, &PropertyCount, &pProPertyIndex))
// 						{
							
							CopyMemory(&diskReadTransfer, pEventData + sizeof(UINT32) + sizeof(UINT32), sizeof(ULONG));
							CopyMemory(&highResResponseTime, pEventData + 24+2*MOF_POINTERSIZE, sizeof(ULONGLONG));

							LARGE_INTEGER Frequency;
							QueryPerformanceFrequency(&Frequency); 

							highResResponseTime = highResResponseTime * 1000000 / Frequency.QuadPart;

							m_totalReadTime += highResResponseTime;
							m_totalReadBytes += diskReadTransfer;
							TimeStamp = pEvent->Header.TimeStamp.QuadPart;

							UINT64 fileObjectPtr = 0;
							CopyMemory(&fileObjectPtr, pEventData + 24, MOF_POINTERSIZE);



							MAP_FILEOBJ_ITE mapIte = m_mapFileObjectToFileName.begin();
							for(; mapIte != m_mapFileObjectToFileName.end() ; ++mapIte)
							{
								if(mapIte->first == fileObjectPtr)
									break;
							}

							if(mapIte == m_mapFileObjectToFileName.end())
							{
								fileIoInfo fileIo;
								ZeroMemory(&fileIo,sizeof(fileIo));
								fileIo.fileIoSize = diskReadTransfer;
								fileIo.fileObjectPtr = fileObjectPtr;
								fileIo.fileIoTime = highResResponseTime;
								m_vecNotFindPtrFile.push_back(fileIo);
							}

							else
							{
								VEC_FILEINFO_ITE ite = m_vecFileIoInfo.begin();
								for(; ite != m_vecFileIoInfo.end(); ++ite)
								{
									if(ite->fileObjectPtr == fileObjectPtr && wcscmp(ite->fileName.c_str(), mapIte->second.c_str()) == 0 )
									{
										ite->fileIoSize += diskReadTransfer;
										ite->fileIoTime += highResResponseTime;
										break;
									}
								}
								if(ite == m_vecFileIoInfo.end())
								{
									fileIoInfo fileIo;
									ZeroMemory(&fileIo,sizeof(fileIo));
									fileIo.fileName = mapIte->second;
									fileIo.fileIoSize = diskReadTransfer;
									fileIo.fileObjectPtr = fileObjectPtr;
									fileIo.fileIoTime = highResResponseTime;
									m_vecFileIoInfo.push_back(fileIo);
								}
							}


// 							PBYTE pEndEventData = pEventData + pEvent->MofLength;
// 							PBYTE pEventPre = pEventData;
// 							for(int i=0; i < PropertyCount; ++i)
// 							{
// 								PrintPropertyName(pProperties + pProPertyIndex[i]);
// 								pEventData = PrintEventPropertyValue(pProperties + pProPertyIndex[i], pEventData, pEndEventData - pEventData);
// 								wprintf(L"ofsset of property :%d", pEventData - pEventPre);
// 							}
// 
// 						}
// 					}
// 				}
			}
		}
	}

}

VOID CConsumer::SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{

	if (NULL == lpSystemInfo)
		return;  
	typedef VOID (WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo); 
	LPFN_GetNativeSystemInfo nsInfo = 
		(LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(_T("kernel32")), "GetNativeSystemInfo");;  
	if (NULL != nsInfo)  
	{  
		nsInfo(lpSystemInfo);  
	}  
	else  
	{  
		GetSystemInfo(lpSystemInfo);  
	}  


}

int CConsumer::GetSystemBits()
{

	SYSTEM_INFO si;  
	SafeGetNativeSystemInfo(&si);  
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||  
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )  
	{  
		return 64;  
	}  
	return 32;  


}

bool pr(SAMPLE_STACK& sam1, SAMPLE_STACK& sam2)
{
	return sam1.timeInterval < sam2.timeInterval;
}

void CConsumer::OutputResult()
{
	sort(m_vecSampleStack.begin(), m_vecSampleStack.end(), pr);


	wprintf((L"GetTotalRead Time = %I64u \r\n"), GetTotalReadTime());
	wprintf((L"GetTotalRead Bytes = %I64u \r\n"), GetTotalReadBytes());
	wprintf(L"Get Cpu Weight = %f\r\n", GetCpuWeight());
	wprintf(L"total sample event = %I64u\r\n", m_totalSampleCount);


	std::wstring currentWorkFolder = m_logFilePath;
	int index = currentWorkFolder.rfind(L"\\");
	currentWorkFolder = currentWorkFolder.substr(0,index+1);

	std::wstring summaryFile = currentWorkFolder + L"summary.txt";
	FILE *fp = _wfopen(summaryFile.c_str(), L"a+");
	if(NULL == fp)
	{
		wprintf(L"openFile Error File Name = %s\r\n",summaryFile.c_str());
		return;
	}
	else
	{
		fprintf(fp, "Start Time Used=%I64u ms\r\n", m_startTimeUsed.QuadPart / 10000);
		fprintf(fp, "Io Time Used=%I64u\r\n", m_totalReadTime);
		fprintf(fp, "Cpu Time Used=%I64u ms, weight =%f\r\n",(UINT64)(GetCpuWeight()/100*m_startTimeUsed.QuadPart/10000), GetCpuWeight());
		fprintf(fp, "-----------------------华丽的分割线---------------------------\r\n\r\n");

		for(std::vector<fileIoInfo>::iterator ite = m_vecNotFindPtrFile.begin(); ite != m_vecNotFindPtrFile.end(); ++ite)
		{
			MAP_FILEOBJ_ITE mapIte = m_mapFileObjectToFileName.begin();
			for(; mapIte != m_mapFileObjectToFileName.end() ; ++mapIte)
			{
				if(mapIte->first == ite->fileObjectPtr)
					break;
			}
			if(mapIte == m_mapFileObjectToFileName.end())
			{
				wprintf(L"FileIo Not Found File\r\n");
				continue;
			}
			VEC_FILEINFO_ITE ite2 = m_vecFileIoInfo.begin();
			for(ite2 = m_vecFileIoInfo.begin(); ite2 != m_vecFileIoInfo.end(); ++ite2)
			{
				if(wcscmp(ite2->fileName.c_str(), mapIte->second.c_str())== 0)
				{
					break;
				}
			}
			if(ite2 != m_vecFileIoInfo.end())
			{
				ite2->fileIoSize += ite->fileIoSize;
				ite2->fileIoTime += ite->fileIoTime;
			}
			else
			{
				fileIoInfo fileInfo;
				fileInfo.fileIoSize = ite->fileIoSize;
				fileInfo.fileIoTime = ite->fileIoTime;
				fileInfo.fileName = mapIte->second;
				fileInfo.fileObjectPtr = ite->fileObjectPtr;
				m_vecFileIoInfo.push_back(fileInfo);
			}
		}
		fprintf(fp, "DiskIo Summary：fileCount=%d\r\n",m_vecFileIoInfo.size());
		fprintf(fp, "Size           IoTime           FileName\r\n");
		for(std::vector<fileIoInfo>::iterator ite = m_vecFileIoInfo.begin(); ite != m_vecFileIoInfo.end(); ++ite)
		{
			fwprintf(fp, L"%-12I64u  ,%-12I64u    ,%s\r\n",ite->fileIoSize, ite->fileIoTime,ite->fileName.c_str());
		}
	}
	fprintf(fp, "\r\n--------------------------------又是华丽的分割线---------------------------------\r\n\r\n");

	int nCount = 0;
	VEC_SAMPLESTACK_ITE ite = m_vecSampleStack.begin();
	for(nCount=0, ite = m_vecSampleStack.begin(); nCount < 10 && ite != m_vecSampleStack.end(); ++nCount, ++ite)
	{
		fprintf(fp, "\r\nStack %d:\r\n", nCount);
		for(std::vector<std::string>::iterator ite2 = ite->vecStack.begin(); ite2 != ite->vecStack.end(); ++ite2)
		{
			fprintf(fp, "%s\r\n", ite2->c_str());
		}
	}

	fprintf(fp, "\r\n---------------------------------------还是华丽的分割线--------------------------------------------------\r\n\r\n");

 	for(VEC_HARDFAULTS_ITE ite = m_vecHardFaults.begin(); ite != m_vecHardFaults.end(); ++ite)
 	{
 		MAP_FILEOBJ_ITE mapIte = m_mapFileObjectToFileName.begin();
 		for(; mapIte != m_mapFileObjectToFileName.end() ; ++mapIte)
 		{
 			if(mapIte->first == ite->fileObj)
 				break;
 		}
 		if(mapIte == m_mapFileObjectToFileName.end())
 		{
 			wprintf(L"Hard Faults Not Found File\r\n");
 			continue;
 		}
 		VEC_FILEFAULTS_ITE iteFaults;
		for(iteFaults = m_vecFileFaults.begin(); iteFaults != m_vecFileFaults.end(); ++iteFaults)
		{
			if(wcscmp(iteFaults->fileName.c_str(), mapIte->second.c_str()) == 0)
				break;
		}
 		if(iteFaults != m_vecFileFaults.end())
 		{
 			iteFaults->faultCount += 1;
 			iteFaults->readSize += ite->byteCount;
 			iteFaults->fileName = mapIte->second;
 			iteFaults->vec_Fault.push_back(*ite);
 		}
 		else
 		{
 			CFileHardFaults fileHardFaults;
 			fileHardFaults.faultCount = 1;
 			fileHardFaults.readSize = ite->byteCount;
 			fileHardFaults.fileName = mapIte->second;
 			fileHardFaults.vec_Fault.push_back(*ite);
 			m_vecFileFaults.push_back(fileHardFaults);
 		}
 
 
 	}

	fprintf(fp,"Count        Size        Name\r\n");

	for(VEC_FILEFAULTS_ITE iteFaults = m_vecFileFaults.begin(); iteFaults != m_vecFileFaults.end(); ++iteFaults)
	{
		fwprintf(fp, L"%-12u  ,%-12I64u    ,%s\r\n",iteFaults->faultCount, iteFaults->readSize,iteFaults->fileName.c_str());
	}

	fclose(fp);

// 	char logFilePath[MAX_PATH] = {0};
// 	std::string command;
// 	WideCharToMultiByte(CP_ACP,0, m_logFilePath.c_str(), -1, logFilePath, MAX_PATH, NULL, FALSE);

// 	command = "xperf -i ";
// 	command = command + logFilePath;
// 	int len = strlen(logFilePath);
// 	logFilePath[len-1] = 't';
// 	logFilePath[len-2] = 'x';
// 	logFilePath[len-3] = 't';
// 	command = command + " -o " + logFilePath + " -a stack";
// 	char cProcessId[64] = {0};
// 	_itoa_s(m_processId, cProcessId, 10);
// 	command = command + " -pid " + cProcessId;
// 	system(command.c_str());
}