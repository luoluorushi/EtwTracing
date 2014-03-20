#include <comutil.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <vector>
#include <map>

static int MOF_POINTERSIZE = 8;

// Points to WMI namespace that contains the ETW MOF classes.
extern IWbemServices* g_pServices;


typedef struct _sampleStack
{
	UINT64	timeStamp;
	UINT64	timeInterval;
	std::vector<std::string>	vecStack;
}SAMPLE_STACK;

typedef struct _propertyList
{
	BSTR Name;
	LONG CimType;
	IWbemQualifierSet *pQualifiers;
}PROPERTY_LIST;

typedef std::wstring tstring;

typedef struct _fileIoInfo
{
	UINT64 fileObjectPtr;
	tstring fileName;
	UINT64 fileIoTime;
	UINT64 fileIoSize;
}fileIoInfo;

typedef struct _hardfaults
{
	UINT64 initTime;
	UINT64 fileOffset;
	UINT64 vtAddress;;
	UINT64 fileObj;
	UINT64 byteCount;
}CHardFaults;

typedef struct _fileHardfaults
{
	UINT64 fileObj;
	UINT64 readSize;
	UINT32 faultCount;
	tstring fileName;
	std::vector<CHardFaults> vec_Fault;
}CFileHardFaults;



template<typename  TConsumer>
class CConsumerWrap
{

public:
	static CConsumerWrap<TConsumer>* GetInstance();
	BOOL ParseTraceFile(LPWSTR logFilePath,DWORD processId);

private:
	CConsumerWrap<TConsumer>();
	TConsumer* m_ConsumerImpl;
	static void WINAPI ProcessEvent(PEVENT_TRACE pEvent);
	static ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer);
	static CConsumerWrap<TConsumer>* sm_instance;
};

class CConsumer
{
public:
	CConsumer();
	void WINAPI ProcessEvent(PEVENT_TRACE pEvent);
	ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer);
	HRESULT ConnectToETWNameSpace(BSTR bstrNameSpace);
	BOOL ConsumerProcessTrace(TRACEHANDLE hTrace, DWORD processId, LPWSTR logFilePath);

private:
	void OutputResult();
	UINT64 GetTotalReadTime() { return m_totalReadTime; }
	UINT64 GetTotalReadBytes() { return m_totalReadBytes; }
	float GetCpuWeight() {return (float)(m_processSampleCount)*100/m_totalSampleCount ;}

private:
	IWbemClassObject* GetEventCategoryClass(BSTR bstrclassGuid, int Version);
	IWbemClassObject* GetEventClass(IWbemClassObject* pEventCategoryClass, int EventType);
	BOOL GetPropertyList(IWbemClassObject *pClass, PROPERTY_LIST **ppProperties, DWORD *pPropertyCount, LONG **ppPropertyIndex);
	void FreePropertyList(PROPERTY_LIST* pProperties, DWORD Count, LONG* pIndex);
	PBYTE CConsumer::PrintEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes);
	void PrintPropertyName(PROPERTY_LIST* pProperty);
	int GetSystemBits();

	VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo);

private:
	UINT64 m_totalReadTime;
	UINT64 m_totalReadBytes;
	BOOL m_isContinueTrace;
	ULONGLONG m_timeStamp;
	ULONGLONG m_beginTimeStamp;
	ULONGLONG m_endTimeStamp;
	ULONGLONG m_totalSampleCount;
	ULONGLONG m_processSampleCount;
	std::wstring m_logFilePath;
	std::vector<DWORD> m_vecThreadId;
	std::vector<fileIoInfo> m_vecFileIoInfo;
	std::map<UINT64,tstring> m_mapFileObjectToFileName;
	std::map<UINT64,tstring> m_mapFileCreate;
	DWORD m_processId;
	HANDLE m_processHandle;
	UINT32 m_stackMatchCount;
	std::vector<std::string> m_vecMatchStack;
	LARGE_INTEGER m_startTimeUsed;
	LARGE_INTEGER m_processStartSamp;
	UINT64 m_preStackWalkStamp;

	std::vector<SAMPLE_STACK> m_vecSampleStack;

	typedef std::map<UINT64,tstring>::iterator MAP_FILEOBJ_ITE;
	typedef std::vector<fileIoInfo>::iterator VEC_FILEINFO_ITE;
	typedef std::vector<SAMPLE_STACK>::iterator VEC_SAMPLESTACK_ITE;

	std::vector<CHardFaults> m_vecHardFaults;
	typedef std::vector<CHardFaults>::iterator VEC_HARDFAULTS_ITE;

	std::vector<CFileHardFaults> m_vecFileFaults;
	typedef std::vector<CFileHardFaults>::iterator VEC_FILEFAULTS_ITE;


};

template<typename  TConsumer>
CConsumerWrap<TConsumer>* CConsumerWrap<TConsumer>::sm_instance = NULL;

template<typename TConsumer>
CConsumerWrap<TConsumer>::CConsumerWrap()
{

}

template<typename TConsumer>
CConsumerWrap<TConsumer>* CConsumerWrap<TConsumer>::GetInstance()
{
	if(sm_instance)
		return sm_instance;
	else
	{
		sm_instance = new CConsumerWrap<TConsumer>();
		sm_instance->m_ConsumerImpl = new TConsumer();
		return sm_instance;
	}
}

template<typename  TConsumer>
void WINAPI CConsumerWrap<TConsumer>::ProcessEvent(PEVENT_TRACE pEvent)
{
	CConsumerWrap<TConsumer>::GetInstance()->m_ConsumerImpl->ProcessEvent(pEvent);
}

template<typename TConsumer>
ULONG WINAPI CConsumerWrap<TConsumer>::ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer)
{
	return CConsumerWrap<TConsumer>::GetInstance()->m_ConsumerImpl->ProcessBuffer(pBuffer);
}

template<typename TConsumer>
BOOL CConsumerWrap<TConsumer>::ParseTraceFile(LPWSTR logFilePath, DWORD processId)
{
	ULONG status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	TRACEHANDLE hTrace = NULL;
	HRESULT hr = S_OK;
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LogFileName = logFilePath;
	trace.BufferCallback =(PEVENT_TRACE_BUFFER_CALLBACK) (ProcessBuffer);
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvent);

	hTrace = OpenTrace(&trace);
	if((TRACEHANDLE)INVALID_HANDLE_VALUE == hTrace)
	{
		wprintf(L"OpenTrace FAILED with %u\r\n", GetLastError());
		goto cleanup;
	}

	m_ConsumerImpl->ConsumerProcessTrace(hTrace, processId, logFilePath);
cleanup:
	if((TRACEHANDLE)INVALID_HANDLE_VALUE != hTrace)
	{
		status = CloseTrace(hTrace);
	}

	if(g_pServices)
	{
		g_pServices->Release();
		g_pServices = NULL;
	}
	return TRUE;
}
