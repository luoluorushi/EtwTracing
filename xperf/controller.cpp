#include "stdafx.h"
#include "controller.h"
#include "provider.h"

BOOL CController::sm_IsFinishTrace = FALSE;

void WINAPI CController::s_ProcessPrivateEvent(PEVENT_TRACE pEvent)
{
	if(IsEqualGUID(pEvent->Header.Guid, MyCategoryGuid))
	{
		if( THUNDER_PROVIDER_TYPE_END == pEvent->Header.Class.Type )
		{
			sm_IsFinishTrace = TRUE;
		}
	}
}

ULONG WINAPI CController::s_ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer)
{
	return !sm_IsFinishTrace;
}


CController::CController() : m_isTraceOn(FALSE), m_pKeSessionProperties(NULL), m_keSessionHandle(NULL), m_prSessionHandle(NULL), m_pPrSessionProperties(NULL)
{
	SYSTEMTIME sys;
	GetLocalTime( &sys );
	wchar_t localTime[256] = {0};
	wsprintf(localTime, L"%04d-%02d-%02d-%02d-%02d-%02d", sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond);
	m_logFolder = ALLLOG_PATH;
	m_logFolder = m_logFolder + localTime;
	SHCreateDirectoryEx(NULL, m_logFolder.c_str(), NULL);
}

BOOL CController::CtrStartTrace(std::wstring programPath, std::wstring &logFilePath, DWORD* processId)
{
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE SessionHandle = 0;
	EVENT_TRACE_PROPERTIES *pSessionProperties = NULL;
	ULONG BufferSize = 0;


	//	提升应用程序权限

	HANDLE token;
	//GetCurrentProcess()函数返回本进程的伪句柄
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token))
		return FALSE;
	LUID luid;

	if(!LookupPrivilegeValue(NULL,SE_SYSTEM_PROFILE_NAME,&luid))
		return FALSE;

	TOKEN_PRIVILEGES pToken;
	pToken.PrivilegeCount=1;
	pToken.Privileges[0].Luid=luid;
	pToken.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(token,FALSE,&pToken,NULL,NULL,NULL))
		return FALSE;


	logFilePath = m_logFolder + L"\\merge.etl";
	m_mergeFile = logFilePath;
	std::wstring sysinfoFile = m_logFolder + L"\\" + SYSINFO_FILE;
	std::wstring privateInfoFile = m_logFolder + L"\\" + PRIVATEINFO_FILE;

	BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME) + (1+sysinfoFile.length()) * sizeof(wchar_t) ;

	//BufferSize =  sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SYSINFO_FILE) + sizeof(LOGSESSION_NAME);
	pSessionProperties = (EVENT_TRACE_PROPERTIES *)malloc(BufferSize);

	if(NULL == pSessionProperties)
	{
		wprintf(L"Unalbe to allocate %d bytes for properties structure", BufferSize);
		CtrCleanUp();
		return FALSE;
	}

	ZeroMemory(pSessionProperties, BufferSize);
	pSessionProperties->Wnode.BufferSize = BufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1;	//QPC clock resolusion
	pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
	pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
	pSessionProperties->MaximumFileSize = 128;
	pSessionProperties->FlushTimer = 1;
	pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO
								 	  | EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS | EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS | EVENT_TRACE_FLAG_PROCESS_COUNTERS | EVENT_TRACE_FLAG_CSWITCH 
									  | EVENT_TRACE_FLAG_DPC| EVENT_TRACE_FLAG_SYSTEMCALL | EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT
									  | EVENT_TRACE_FLAG_FORWARD_WMI | EVENT_TRACE_FLAG_SPLIT_IO | EVENT_TRACE_FLAG_DISK_IO_INIT | EVENT_TRACE_FLAG_FILE_IO_INIT;
	pSessionProperties->MinimumBuffers = 128;
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
	StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), (sysinfoFile.length()+1) * sizeof(wchar_t), sysinfoFile.c_str());

	m_pKeSessionProperties = pSessionProperties;

	status = StartTrace(&SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties);

	m_keSessionHandle = SessionHandle;

	if(ERROR_SUCCESS != status)
	{
		wprintf(L"Start Trace failed with %lu \r\n", status);
		CtrCleanUp();
		return FALSE;
	}

	CLASSIC_EVENT_ID eventId[10] = {0};
	eventId[0].EventGuid = PerfInfoGuid;
	eventId[0].Type = 46;
	status = TraceSetInformation(m_keSessionHandle, TraceStackTracingInfo,eventId, sizeof(eventId));
	if(ERROR_SUCCESS != status)
	{
		wprintf(L"TraceSetInformation failed with %lu \r\n", status);
	}

	BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGSESSION_NAME) + (1+privateInfoFile.length()) * sizeof(wchar_t) ;
	pSessionProperties = (EVENT_TRACE_PROPERTIES *)malloc(BufferSize);
	ZeroMemory(pSessionProperties, BufferSize);
	pSessionProperties->Wnode.BufferSize = BufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1;	//QPC clock resolusion
	pSessionProperties->Wnode.Guid = SesionGuid;
	pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_REAL_TIME_MODE;
	pSessionProperties->MaximumFileSize = 128;
	pSessionProperties->FlushTimer = 1;
	pSessionProperties->EnableFlags = 0;
	pSessionProperties->MinimumBuffers = 128;
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGSESSION_NAME);
	StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), (1+privateInfoFile.length()) * sizeof(wchar_t) , privateInfoFile.c_str());

	m_pPrSessionProperties = pSessionProperties;

	status = StartTrace(&SessionHandle, LOGSESSION_NAME, pSessionProperties);
	m_prSessionHandle = SessionHandle;
	status = EnableTrace(
		TRUE,
		0,
		TRACE_LEVEL_INFORMATION,
		(LPGUID)&(ProviderGuid),
		SessionHandle);

	if(ERROR_SUCCESS != status)
	{
		wprintf(L"Enable Provider Failed with %lu \r\n", status);
		CtrCleanUp();
		return FALSE;
	}

	programPath = L"\"" + programPath + L"\"";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = {0};
	BOOL isCreateSuccesss = CreateProcessW(NULL ,(LPWSTR)programPath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if(!isCreateSuccesss)
	{
		CtrCleanUp();
		return FALSE;
	}

	*processId = pi.dwProcessId;

	CtrParseTrace();

	return TRUE;

}

void CController::CtrParseTrace()
{
	EVENT_TRACE_LOGFILE logFile;
	ZeroMemory(&logFile, sizeof(EVENT_TRACE_LOGFILE));
	logFile.LoggerName        = (LPWSTR)LOGSESSION_NAME;
	logFile.BufferCallback    = (PEVENT_TRACE_BUFFER_CALLBACK)s_ProcessBuffer;
	logFile.EventCallback     = (PEVENT_CALLBACK)s_ProcessPrivateEvent;
	logFile.ProcessTraceMode  = PROCESS_TRACE_MODE_REAL_TIME;

	while(!sm_IsFinishTrace)
	{
		ULONG ulStatus = ERROR_SUCCESS;
		TRACEHANDLE hTrace = OpenTrace(&logFile);

		if ((ULONGLONG)-1 != hTrace && (ULONGLONG)0x0FFFFFFFF != hTrace) // 不能用INVALID_PROCESSTRACE_HANDLE比较
		{
			while ((ulStatus = ProcessTrace(&hTrace, 1, 0, 0)) == ERROR_SUCCESS)
			{
				if(sm_IsFinishTrace)
					break;
			}

			CloseTrace(hTrace);
		}
		Sleep(200);
	}
	CtrCleanUp();
	MergeTraceFile();
}

void CController::MergeTraceFile()
{
	std::wstring sysinfoFile = m_logFolder + L"\\" + SYSINFO_FILE;
	std::wstring privateInfoFile = m_logFolder + L"\\" + PRIVATEINFO_FILE;

	std::string command;
	char privatePath[MAX_PATH] = {0};
	char sysPath[MAX_PATH] = {0};
	char mergePath[MAX_PATH] = {0};
	WideCharToMultiByte(CP_ACP,0, sysinfoFile.c_str(), -1, sysPath, MAX_PATH, NULL, FALSE);
	WideCharToMultiByte(CP_ACP,0, privateInfoFile.c_str(), -1, privatePath, MAX_PATH, NULL, FALSE);
	WideCharToMultiByte(CP_ACP,0, m_mergeFile.c_str(), -1, mergePath, MAX_PATH, NULL, FALSE);

	command = "xperf -merge ";
	command = command + sysPath + " " + privatePath + " " + mergePath;
	system(command.c_str());
}

void CController::CtrCleanUp()
{
	if(m_keSessionHandle)
	{
		ULONG status = ControlTrace(m_keSessionHandle, NULL, m_pKeSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if(ERROR_SUCCESS != status )
		{
			wprintf(L"Stop Failed with %lu \n", status);
		}
	}

	if(m_prSessionHandle)
	{
		ULONG status = ControlTrace(m_prSessionHandle, NULL, m_pPrSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if(ERROR_SUCCESS != status)
		{
			wprintf(L"Stop Private Session Failed with %lu \r\n", status);
		}
	}

	if(m_pKeSessionProperties)
	{
		free(m_pKeSessionProperties);
		m_pKeSessionProperties = NULL;
	}

	if(m_pPrSessionProperties)
	{
		free(m_pPrSessionProperties);
		m_pPrSessionProperties = NULL;
	}
}