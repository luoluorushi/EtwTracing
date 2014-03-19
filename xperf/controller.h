#include <windows.h>

#include <conio.h>
#include <wmistr.h>
#include <Evntcons.h>
#include <string>
#include <vector>

#include <strsafe.h>
#include <Shlobj.h>
#include "provider.h"

#define SYSINFO_FILE L"System.etl"
#define PRIVATEINFO_FILE L"Private.etl"
#define LOGSESSION_NAME L"Trace Session of Han"

#define ALLLOG_PATH L"d:\\ParseEtl\\";

//{BE71370B-5EC9-4420-8365-5D8F8959A4B8}
static const GUID SesionGuid= 
{ 0xbe71370b, 0x5ec9, 0x4420, { 0x83, 0x65, 0x5d, 0x8f, 0x89, 0x59, 0xa4, 0xb8 } };


//GUID that identifies the provider that you want to enable to your session

// {C5F097E2-6D10-4820-81BE-04A15B6F8DBC}
//static const GUID ProviderGuid = 
//{ 0xc5f097e2, 0x6d10, 0x4820, { 0x81, 0xbe, 0x4, 0xa1, 0x5b, 0x6f, 0x8d, 0xbc } };


class CController
{
public:
	CController();
	BOOL CtrStartTrace(std::wstring programPath, std::wstring &logFilePath, DWORD*);
	
private:
	void MergeTraceFile();
	void CtrCleanUp();
	void CtrParseTrace();


private:
	BOOL m_isTraceOn;
	EVENT_TRACE_PROPERTIES *m_pKeSessionProperties;
	TRACEHANDLE m_keSessionHandle;

	EVENT_TRACE_PROPERTIES *m_pPrSessionProperties;
	TRACEHANDLE m_prSessionHandle;

	static void WINAPI s_ProcessPrivateEvent(PEVENT_TRACE pEvent);
	static ULONG WINAPI s_ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer);
	static BOOL sm_IsFinishTrace;
	std::wstring m_logFolder;
	std::wstring m_mergeFile;
};
