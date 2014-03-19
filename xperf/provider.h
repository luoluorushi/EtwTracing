#pragma  once

#include "targetver.h"
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wmistr.h>
#include <evntrace.h>

#define MAX_INDICES	3
#define MAX_SIGNATURE_LEN	32
#define EVENT_DATA_FIELDS_CNT	16
#define MY_EVENT_TYPE 1


#define THUNDER_PROVIDER_TYPE_BEGIN 1
#define THUNDER_PROVIDER_TYPE_END 2

// {56C6CB14-3AC4-47f5-9AD1-9EF7E728EB0F}
static const GUID MyCategoryGuid = 
{ 0x56c6cb14, 0x3ac4, 0x47f5, { 0x9a, 0xd1, 0x9e, 0xf7, 0xe7, 0x28, 0xeb, 0xf } };


// {C5F097E2-6D10-4820-81BE-04A15B6F8DBC}
static const GUID ProviderGuid = 
{ 0xc5f097e2, 0x6d10, 0x4820, { 0x81, 0xbe, 0x4, 0xa1, 0x5b, 0x6f, 0x8d, 0xbc } };

// {4FBAE9A1-A8FD-4687-A0B3-F813E210E613}
static const GUID tempID = 
{ 0x4fbae9a1, 0xa8fd, 0x4687, { 0xa0, 0xb3, 0xf8, 0x13, 0xe2, 0x10, 0xe6, 0x13 } };



typedef struct _eventdata
{
	LONG Cost;
	DWORD Indices[MAX_INDICES];
	WCHAR Signature[MAX_SIGNATURE_LEN];
	BOOL IsComplete;
	GUID ID;
	DWORD Size;
}EVENT_DATA, *PVEVENT_DATA;

typedef struct _event
{
	EVENT_TRACE_HEADER Header;
	MOF_FIELD Data[MAX_MOF_FIELDS];
}MY_EVENT,*PMY_EVENT;

class	CProvider
{
public:
	static ULONG RegisterProviderGuid();
	static ULONG UnRegisterProviderGuid();
	static ULONG TraceSpecificEvent(UCHAR);

	static ULONG WINAPI ControlCallback(WMIDPREQUESTCODE RequestCode, PVOID pContext, ULONG *Reserved, PVOID Header);

private:

	static TRACEHANDLE sm_traceHandle;
	static BOOL sm_isTraceOn;
	static UCHAR sm_EnableLevel;
	static ULONG sm_EnableFalgs;

};
