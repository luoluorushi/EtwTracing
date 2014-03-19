#include "stdafx.h"

#define INITGUID

#include "provider.h"



TRACEHANDLE CProvider::sm_traceHandle = 0;
BOOL CProvider::sm_isTraceOn = FALSE;
UCHAR CProvider::sm_EnableLevel = 0 ;
ULONG CProvider::sm_EnableFalgs = 0;

ULONG CProvider::RegisterProviderGuid()
{
	TRACE_GUID_REGISTRATION EventClassGuids[] = {(LPGUID)&MyCategoryGuid, NULL}; 
	TRACEHANDLE RegistationHandle = 0;
	ULONG status = RegisterTraceGuids(ControlCallback,NULL,(LPGUID)& ProviderGuid, sizeof(EventClassGuids) / sizeof(TRACE_GUID_REGISTRATION), EventClassGuids, NULL, NULL, &RegistationHandle);

	return status;
}

ULONG CProvider::TraceSpecificEvent(UCHAR classType)
{
	EVENT_DATA EventData;
	EventData.Cost = 32;
	EventData.ID = tempID;
	EventData.Indices[0] = 4;
	EventData.Indices[1] = 5;
	EventData.Indices[2] = 6;
	EventData.IsComplete = TRUE;
	wcscpy_s(EventData.Signature, MAX_SIGNATURE_LEN, L"Signature");
	EventData.Size = 1024;
	if(sm_isTraceOn && (4 == sm_EnableLevel || TRACE_LEVEL_ERROR <= sm_EnableFalgs ))
	{
		MY_EVENT MyEvent;

		// initial the event data structure;

		ZeroMemory(&MyEvent, sizeof(MY_EVENT));
		MyEvent.Header.Size = sizeof(EVENT_TRACE_HEADER) + sizeof(MOF_FIELD) * EVENT_DATA_FIELDS_CNT;
		MyEvent.Header.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR;
		MyEvent.Header.Guid = MyCategoryGuid;
		MyEvent.Header.Class.Type = classType;
		MyEvent.Header.Class.Version = 1;
		MyEvent.Header.Class.Level = sm_EnableLevel;

		// Load the event data
		MyEvent.Data[0].DataPtr = (ULONG64) &(EventData.Cost);
		MyEvent.Data[0].Length = sizeof(EventData.Cost);
		MyEvent.Data[1].DataPtr = (ULONG64) &(EventData.Indices);
		MyEvent.Data[1].Length = sizeof(EventData.Indices);
		MyEvent.Data[2].DataPtr = (ULONG64) &(EventData.Signature);
		MyEvent.Data[2].Length = (ULONG) ((wcslen(EventData.Signature) + 1) *sizeof(WCHAR));
		MyEvent.Data[3].DataPtr = (ULONG64) &(EventData.IsComplete);
		MyEvent.Data[3].Length = sizeof(EventData.IsComplete);
		MyEvent.Data[4].DataPtr = (ULONG64) &(EventData.ID);
		MyEvent.Data[4].Length = sizeof(EventData.ID);
		MyEvent.Data[5].DataPtr = (ULONG64) &(EventData.Size);
		MyEvent.Data[5].Length = sizeof(EventData.Size);

		ULONG status = TraceEvent(sm_traceHandle, &(MyEvent.Header));
		if(ERROR_SUCCESS != status)
		{
			wprintf(L"Trace Failed");
			sm_isTraceOn = FALSE;
		}

		return status;
	}
	return FALSE;
}

ULONG WINAPI CProvider::ControlCallback(WMIDPREQUESTCODE RequestCode, PVOID Context, ULONG *Reserved, PVOID Header)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Reserved);

	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE TempSessionHandle = 0; 

	switch (RequestCode)
	{
	case WMI_ENABLE_EVENTS:  // Enable the provider.
		{
			SetLastError(0);

			// If the provider is already enabled to a provider, ignore 
			// the request. Get the session handle of the enabling session.
			// You need the session handle to call the TraceEvent function.
			// The session could be enabling the provider or it could be
			// updating the level and enable flags.

			TempSessionHandle = GetTraceLoggerHandle(Header);
			if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
			{
				wprintf(L"GetTraceLoggerHandle failed. Error code is %lu.\n", status = GetLastError());
				break;
			}

			if (0 == sm_traceHandle)
			{
				sm_traceHandle = TempSessionHandle;
			}
			else if (sm_traceHandle != TempSessionHandle)
			{
				break;
			}

			// Get the severity level of the events that the
			// session wants you to log.

			sm_EnableLevel = GetTraceEnableLevel(sm_traceHandle); 
			if (0 == sm_EnableLevel)
			{
				// If zero, determine whether the session passed zero
				// or an error occurred.

				if (ERROR_SUCCESS == (status = GetLastError()))
				{
					// Decide what a zero enable level means to your provider.
					// For this example, it means log all events.
					; 
				}
				else
				{
					wprintf(L"GetTraceEnableLevel failed with, %lu.\n", status);
					break;
				} 
			}

			// Get the enable flags that indicate the events that the
			// session wants you to log. The provider determines the
			// flags values. How it articulates the flag values and 
			// meanings to perspective sessions is up to it.

			sm_EnableFalgs = GetTraceEnableFlags(sm_traceHandle);
			if (0 == sm_EnableFalgs)
			{
				// If zero, determine whether the session passed zero
				// or an error occurred.

				if (ERROR_SUCCESS == (status = GetLastError()))
				{
					// Decide what a zero enable flags value means to your provider.
					; 
				}
				else
				{
					wprintf(L"GetTraceEnableFlags failed with, %lu.\n", status);
					break;
				}
			}

			sm_isTraceOn = TRUE;
			break;
		}

	case WMI_DISABLE_EVENTS:  // Disable the provider.
		{
			// Disable the provider only if the request is coming from the
			// session that enabled the provider.

			TempSessionHandle = GetTraceLoggerHandle(Header);
			if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
			{
				wprintf(L"GetTraceLoggerHandle failed. Error code is %lu.\n", status = GetLastError());
				break;
			}

			if (sm_traceHandle == TempSessionHandle)
			{
				sm_isTraceOn = FALSE;
				sm_traceHandle = 0;
			}
			break;
		}

	default:
		{
			status = ERROR_INVALID_PARAMETER;
			break;
		}
	}

	return status;
}