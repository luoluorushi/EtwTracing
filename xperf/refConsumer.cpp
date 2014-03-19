//	现在不需要用上，但是有参考意义的代码

#include "stdafx.h"
#include "consumer.h"

void CConsumer::PrintPropertyName(PROPERTY_LIST* pProperty)
{
	HRESULT hr;
	VARIANT varDisplayName;

	// Retrieve the Description qualifier for the property. The description qualifier
	// should contain a printable display name for the property. If the qualifier is
	// not found, print the property name.

	hr = pProperty->pQualifiers->Get(L"Description", 0, &varDisplayName, NULL);
	wprintf(L"%s: ", (SUCCEEDED(hr)) ? varDisplayName.bstrVal : pProperty->Name);
	VariantClear(&varDisplayName);
}

void CConsumer::FreePropertyList(PROPERTY_LIST* pProperties, DWORD Count, LONG* pIndex)
{
	if(pProperties)
	{
		for (DWORD i=0; i < Count; i++)
		{
			SysFreeString((pProperties+i)->Name);

			if ((pProperties+i)->pQualifiers)
			{
				(pProperties+i)->pQualifiers->Release();
				(pProperties+i)->pQualifiers = NULL;
			}
		}

		free(pProperties);
	}

	if (pIndex)
		free(pIndex);
}

BOOL CConsumer::GetPropertyList(IWbemClassObject *pClass, PROPERTY_LIST **ppProperties, DWORD *pPropertyCount, LONG **ppPropertyIndex)
{
	HRESULT hr = S_OK;
	SAFEARRAY *pNames = NULL;
	LONG j = 0; 
	VARIANT var;

	hr = pClass->GetNames(NULL, WBEM_FLAG_LOCAL_ONLY, NULL, &pNames);
	if(pNames)
	{
		*pPropertyCount = pNames->rgsabound->cElements;

		// Allocate a block of memory to hold a array of PROPERTY_LIST structure.

		*ppProperties = (PROPERTY_LIST *) malloc(sizeof(PROPERTY_LIST) * (*pPropertyCount));
		if(NULL == *ppProperties)
		{
			hr = E_OUTOFMEMORY;
			goto cleanup;
		}

		// WMI may not return the properties in the order as defined in the MOF

		*ppPropertyIndex = (LONG*) malloc(sizeof(LONG) * (*pPropertyCount));
		if(NULL == *pPropertyCount)
		{
			hr = E_OUTOFMEMORY;
			goto cleanup;
		}

		for(LONG i=0; i < *pPropertyCount; ++i)
		{
			hr = SafeArrayGetElement(pNames, &i, &((*ppProperties + i)->Name));
			if(FAILED(hr))
			{
				goto cleanup;
			}

			hr = pClass->GetPropertyQualifierSet((*ppProperties+i)->Name,&((*ppProperties + i)->pQualifiers));
			if(FAILED(hr))
			{
				goto cleanup;
			}

			hr = (*ppProperties + i)->pQualifiers->Get(L"WmiDataId", 0, &var, NULL);
			if(SUCCEEDED(hr))
			{
				j = var.intVal - 1;
				VariantClear(&var);
				*(*ppPropertyIndex + j) = i;
			}
			else
			{
				goto cleanup;
			}

			hr = pClass->Get((*ppProperties + i)->Name,0, NULL, &((*ppProperties + i)->CimType), NULL);
			if(FAILED(hr))
			{
				goto cleanup;
			}
		}
	}
cleanup:
	if(pNames)
	{
		SafeArrayDestroy(pNames);
	}
	if(FAILED(hr))
	{
		if(*ppProperties)
		{
			FreePropertyList(*ppProperties, *pPropertyCount, *ppPropertyIndex);
		}
		return FALSE;
	}
	return TRUE;
}

IWbemClassObject* CConsumer::GetEventClass(IWbemClassObject* pEventCategoryClass, int EventType)
{
	HRESULT hr = S_OK;
	HRESULT hrQualifier = S_OK;
	IEnumWbemClassObject *pClasses = NULL;
	IWbemClassObject *pClass = NULL;
	IWbemQualifierSet *pQualifiers = NULL;
	VARIANT varClassName;
	VARIANT varEventType;
	ULONG cnt = 0;
	BOOL FoundEventClass = FALSE;

	hr = pEventCategoryClass->Get(L"__RELPATH", 0, &varClassName,NULL,NULL);
	if(FAILED(hr))
	{ 
		wprintf(L"pEventCategory->Get failed with 0x%x\r\n", hr);
		goto cleanup;
	}
	hr = g_pServices->CreateClassEnum(varClassName.bstrVal,
		WBEM_FLAG_SHALLOW | WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
		NULL, &pClasses);

	if(FAILED(hr))
	{
		wprintf(L"g_pServices->CreateClassEnum failed with 0x%x\r\n", hr);
		goto cleanup;
	}

	while(S_OK == hr)
	{
		hr = pClasses->Next(WBEM_INFINITE,1, &pClass, &cnt);
		if(FAILED(hr))
		{
			wprintf(L"pClass->Next Failed with 0x%x\r\n", hr);
			goto cleanup;
		}
		if(!pClass)
			continue;
		hrQualifier = pClass->GetQualifierSet(&pQualifiers);
		if(FAILED(hrQualifier))
		{
			wprintf(L"pClass->GetQualifierSet Failed with 0x%x\r\n", hrQualifier);
			pClass->Release();
			pClass = NULL;
			goto cleanup;
		}

		hrQualifier = pQualifiers->Get(L"EventType", 0, &varEventType, NULL);
		if(FAILED(hrQualifier))
		{
			wprintf(L"pQualifiers->Get Failed with 0x%x\r\n", hrQualifier);
			pQualifiers->Release();
			pQualifiers = NULL;
			pClass->Release();
			pClass = NULL;
			goto cleanup;
		}

		// If multiple events provide the same data, the EventType qualifier
		// will contain an array of types. Loop through the array and find a match.

		if (varEventType.vt & VT_ARRAY)
		{
			HRESULT hrSafe = S_OK;
			int ClassEventType;
			SAFEARRAY* pEventTypes = varEventType.parray;

			for (LONG i=0; (ULONG)i < pEventTypes->rgsabound->cElements; i++)
			{
				hrSafe = SafeArrayGetElement(pEventTypes, &i, &ClassEventType);

				if (ClassEventType == EventType)
				{
					FoundEventClass = TRUE;
					break;  //for loop
				}
			}
		}
		else
		{
			if (varEventType.intVal == EventType)
			{
				FoundEventClass = TRUE;
			}
		}

		VariantClear(&varEventType);

		if (TRUE == FoundEventClass)
		{
			break;  //while loop
		}

		pClass->Release();
		pClass = NULL;

	}
cleanup:
	if (pClasses)
	{
		pClasses->Release();
		pClasses = NULL;
	}

	if (pQualifiers)
	{
		pQualifiers->Release();
		pQualifiers = NULL;
	}

	VariantClear(&varClassName);
	VariantClear(&varEventType);

	return pClass;
}

IWbemClassObject* CConsumer::GetEventCategoryClass(BSTR bstrclassGuid, int Version)
{
	HRESULT hr = S_OK;
	HRESULT hrQualifier = S_OK;
	IEnumWbemClassObject* pClasses = NULL;
	IWbemClassObject* pClass = NULL;
	IWbemQualifierSet* pQualifiers = NULL;
	ULONG cnt = 0;
	VARIANT varGuid;
	VARIANT varVersion;

	hr = g_pServices->CreateClassEnum(_bstr_t(L"EventTrace"),
		WBEM_FLAG_DEEP | WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
		NULL, &pClasses);

	if(FAILED(hr))
	{
		wprintf(L"CreateClassEnum failed with 0x%x\r\n", hr);
		goto cleanup;
	}
	while(S_OK == hr)
	{
		hr = pClasses->Next(WBEM_INFINITE, 1, &pClass, &cnt);
		if(FAILED(hr))
		{
			wprintf(L"pClasses->Next Failed with 0x%x\r\n", hr);
			goto cleanup;
		}
		hrQualifier = pClass->GetQualifierSet(&pQualifiers);
		if(pQualifiers)
		{
			hrQualifier = pQualifiers->Get(L"Guid", 0, &varGuid, NULL);
			if(SUCCEEDED(hrQualifier) && 0 == _wcsicmp(varGuid.bstrVal, bstrclassGuid))
			{
				hrQualifier = pQualifiers->Get(L"EventVersion", 0, &varVersion, NULL);
				if(SUCCEEDED(hrQualifier))
				{
					if(Version == varVersion.intVal)
					{
						break;
					}
					VariantClear(&varVersion);
				}
				else if(WBEM_E_NOT_FOUND == hrQualifier)
				{
					break;
				}
				VariantClear(&varGuid);
			}
			pQualifiers->Release();
			pQualifiers = NULL;
		}
		pClass->Release();
		pClass = NULL;
	}
cleanup:
	if(pClasses)
	{
		pClasses->Release();
		pClasses = NULL;
	}
	if(pQualifiers)
	{
		pQualifiers->Release();
		pQualifiers = NULL;
	}
	VariantClear(&varGuid);
	VariantClear(&varVersion);
	return pClass;
}

HRESULT CConsumer::ConnectToETWNameSpace(BSTR bstrNameSpace)
{
	HRESULT hr = S_OK;
	IWbemLocator *pLocator = NULL;
	hr = CoInitialize(0);
	hr = CoCreateInstance(__uuidof(WbemLocator), 
		0,
		CLSCTX_INPROC_SERVER,
		__uuidof(IWbemLocator),
		(LPVOID*) &pLocator);

	if(FAILED(hr))
	{
		wprintf(L"CoCreateInstance failed with 0x%x\r\n", hr);
		goto cleanup;
	}

	hr = pLocator->ConnectServer(bstrNameSpace,
		NULL,NULL,NULL,0L,NULL,NULL,&g_pServices);

	if(FAILED(hr))
	{
		wprintf(L"Connect toServer Failed with 0x%x\r\n",hr);
		goto cleanup;
	}

	hr = CoSetProxyBlanket(g_pServices,
		RPC_C_AUTHN_WINNT,RPC_C_AUTHN_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE);

	if(FAILED(hr))
	{
		wprintf(L"CoSetProxBlanket Failed with 0x%x\r\n", hr);
		g_pServices->Release();
		g_pServices = NULL;
	}

cleanup:
	if(pLocator)
		pLocator->Release();

	return hr;
}

ULONG g_PointerSize = 4;

PBYTE CConsumer::PrintEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes)
{
	HRESULT hr;
	VARIANT varQualifier;
	ULONG ArraySize = 1;
	BOOL PrintAsChar = FALSE;
	BOOL PrintAsHex = FALSE;
	BOOL PrintAsIPAddress = FALSE; 
	BOOL PrintAsPort = FALSE; 
	BOOL IsWideString = FALSE;
	BOOL IsNullTerminated = FALSE;
	USHORT StringLength = 0;

	// If the property contains the Pointer or PointerType qualifier,
	// you do not need to know the data type of the property. You just
	// retrieve either four bytes or eight bytes depending on the 
	// pointer's size.

	if (SUCCEEDED(hr = pProperty->pQualifiers->Get(L"Pointer", 0, NULL, NULL)) ||
		SUCCEEDED(hr = pProperty->pQualifiers->Get(L"PointerType", 0, NULL, NULL)))
	{
		// 		if (g_PointerSize == 4) 
		// 		{
		// 			ULONG temp = 0;
		// 
		// 			CopyMemory(&temp, pEventData, sizeof(ULONG));
		// 			wprintf(L"0x%x\n", temp);
		// 		}
		// 		else
		// 		{
		// 			ULONGLONG temp = 0;
		// 
		// 			CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
		// 			wprintf(L"0x%x\n", temp);
		// 		}

		pEventData += 8;

		return pEventData;
	}
	else
	{
		// If the property is an array, retrieve its size. The ArraySize variable
		// is initialized to 1 to force the loops below to print the value
		// of the property.

		if (pProperty->CimType & CIM_FLAG_ARRAY)
		{
			hr = pProperty->pQualifiers->Get(L"MAX", 0, &varQualifier, NULL);
			if (SUCCEEDED(hr))
			{
				ArraySize = varQualifier.intVal;
				VariantClear(&varQualifier);
			}
			else
			{
				wprintf(L"Failed to retrieve the MAX qualifier. Terminating.\n");
				return NULL;
			}
		}

		// The CimType is the data type of the property.

		switch(pProperty->CimType & (~CIM_FLAG_ARRAY))
		{
		case CIM_SINT32:
			{
				LONG temp = 0;

				for (ULONG i=0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(LONG));
					wprintf(L"%d\n", temp);
					pEventData += sizeof(LONG);
				}

				return pEventData;
			}

		case CIM_UINT32:
			{
				ULONG temp = 0;

				hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
				if (SUCCEEDED(hr))
				{
					// Some kernel events pack an IP address into a UINT32.
					// Check for an Extension qualifier whose value is IPAddr.
					// This is here to support legacy event classes; the IPAddr extension 
					// should only be used on properties whose CIM type is object.

					if (_wcsicmp(L"IPAddr", varQualifier.bstrVal) == 0)
					{
						PrintAsIPAddress = TRUE;
					}

					VariantClear(&varQualifier);
				}
				else
				{
					hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
					if (SUCCEEDED(hr))
					{
						PrintAsHex = TRUE;
					}
				}

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(ULONG));

					if (PrintAsIPAddress)
					{
						wprintf(L"%03d.%03d.%03d.%03d\n", (temp >>  0) & 0xff,
							(temp >>  8) & 0xff,
							(temp >>  16) & 0xff,
							(temp >>  24) & 0xff);
					}
					else if (PrintAsHex)
					{
						wprintf(L"0x%x\n", temp);
					}
					else
					{
						wprintf(L"%lu\n", temp);
					}

					pEventData += sizeof(ULONG);
				}

				return pEventData;
			}

		case CIM_SINT64:
			{
				LONGLONG temp = 0;

				for (ULONG i=0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(LONGLONG));
					wprintf(L"%I64d\n", temp);
					pEventData += sizeof(LONGLONG);
				}

				return pEventData;
			}

		case CIM_UINT64:
			{
				ULONGLONG temp = 0;

				for (ULONG i=0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
					wprintf(L"%I64u\n", temp);
					pEventData += sizeof(ULONGLONG);
				}

				return pEventData;
			}

		case CIM_STRING:
			{
				USHORT temp = 0;

				// The format qualifier is included only if the string is a wide string.

				hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
				if (SUCCEEDED(hr))
				{
					IsWideString = TRUE;
				}

				hr = pProperty->pQualifiers->Get(L"StringTermination", 0, &varQualifier, NULL);
				if (FAILED(hr) || (_wcsicmp(varQualifier.bstrVal, L"NullTerminated") == 0))
				{
					IsNullTerminated = TRUE;
				}
				else if (_wcsicmp(varQualifier.bstrVal, L"Counted") == 0)
				{
					// First two bytes of the string contain its length.

					CopyMemory(&StringLength, pEventData, sizeof(USHORT));
					pEventData += sizeof(USHORT);
				}
				else if (_wcsicmp(varQualifier.bstrVal, L"ReverseCounted") == 0)
				{
					// First two bytes of the string contain its length.
					// Count is in big-endian; convert to little-endian.

					CopyMemory(&temp, pEventData, sizeof(USHORT));
					StringLength = MAKEWORD(HIBYTE(temp), LOBYTE(temp));
					pEventData += sizeof(USHORT);
				}
				else if (_wcsicmp(varQualifier.bstrVal, L"NotCounted") == 0)
				{
					// The string is not null-terminated and does not contain
					// its own length, so its length is the remaining bytes of
					// the event data. 

					StringLength = RemainingBytes;
				}

				VariantClear(&varQualifier);

				for (ULONG i = 0; i < ArraySize; i++)
				{
					if (IsWideString)
					{
						if (IsNullTerminated)
						{
							StringLength = (USHORT)wcslen((WCHAR*)pEventData) + 1;
							wprintf(L"%s\n", (WCHAR*)pEventData);
						}
						else
						{
							LONG StringSize = (StringLength) * sizeof(WCHAR); 
							WCHAR* pwsz = (WCHAR*)malloc(StringSize+2); // +2 for NULL

							if (pwsz)
							{
								CopyMemory(pwsz, (WCHAR*)pEventData, StringSize); 
								*(pwsz+StringSize) = '\0';
								wprintf(L"%s\n", pwsz);
								free(pwsz);
							}
							else
							{
								// Handle allocation error.
							}
						}

						StringLength *= sizeof(WCHAR);
					}
					else  // It is an ANSI string
					{
						if (IsNullTerminated)
						{
							StringLength = (USHORT)strlen((char*)pEventData) + 1;
							printf("%s\n", (char*)pEventData);
						}
						else
						{
							char* psz = (char*)malloc(StringLength+1);  // +1 for NULL

							if (psz)
							{
								CopyMemory(psz, (char*)pEventData, StringLength);
								*(psz+StringLength) = '\0';
								printf("%s\n", psz);
								free(psz);
							}
							else
							{
								// Handle allocation error.
							}
						}
					}

					pEventData += StringLength;
					StringLength = 0;
				}

				return pEventData;
			} 

		case CIM_BOOLEAN:
			{
				BOOL temp = FALSE;

				for (ULONG i=0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(BOOL));
					wprintf(L"%s\n", (temp) ? L"TRUE" : L"FALSE");
					pEventData += sizeof(BOOL);
				}

				return pEventData;
			}

		case CIM_SINT8:
		case CIM_UINT8:
			{
				hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
				if (SUCCEEDED(hr))
				{
					// This is here to support legacy event classes; the Guid extension 
					// should only be used on properties whose CIM type is object.

					if (_wcsicmp(L"Guid", varQualifier.bstrVal) == 0)
					{
						WCHAR szGuid[50];
						GUID Guid;

						CopyMemory(&Guid, (GUID*)pEventData, sizeof(GUID));
						StringFromGUID2(Guid, szGuid, sizeof(szGuid)-1);
						wprintf(L"%s\n", szGuid);
					}

					VariantClear(&varQualifier);
					pEventData += sizeof(GUID);
				}
				else 
				{
					hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
					if (SUCCEEDED(hr))
					{
						PrintAsChar = TRUE;  // ANSI character
					}

					for (ULONG i = 0; i < ArraySize; i++)
					{
						if (PrintAsChar)
							wprintf(L"%c", *((char*)pEventData)); 
						else
							wprintf(L"%hd", *((BYTE*)pEventData));

						pEventData += sizeof(UINT8);
					}
				}

				wprintf(L"\n");

				return pEventData;
			}

		case CIM_CHAR16:
			{
				WCHAR temp;

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(WCHAR));
					wprintf(L"%c", temp);
					pEventData += sizeof(WCHAR);
				}

				wprintf(L"\n");

				return pEventData;
			}

		case CIM_SINT16:
			{
				SHORT temp = 0;

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(SHORT));
					wprintf(L"%hd\n", temp);
					pEventData += sizeof(SHORT);
				}

				return pEventData;
			}

		case CIM_UINT16:
			{
				USHORT temp = 0;

				// If the data is a port number, call the ntohs Windows Socket 2 function
				// to convert the data from TCP/IP network byte order to host byte order.
				// This is here to support legacy event classes; the Port extension 
				// should only be used on properties whose CIM type is object.

				hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
				if (SUCCEEDED(hr))
				{
					if (_wcsicmp(L"Port", varQualifier.bstrVal) == 0)
					{
						PrintAsPort = TRUE;
					}

					VariantClear(&varQualifier);
				}

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(USHORT));

					if (PrintAsPort)
					{
						wprintf(L"%hu\n", ntohs(temp));
					}
					else
					{
						wprintf(L"%hu\n", temp);
					}

					pEventData += sizeof(USHORT);
				}

				return pEventData;
			}

		case CIM_OBJECT:
			{
				// An object data type has to include the Extension qualifier.

				hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
				if (SUCCEEDED(hr))
				{
					if (_wcsicmp(L"SizeT", varQualifier.bstrVal) == 0)
					{
						VariantClear(&varQualifier);

						// You do not need to know the data type of the property, you just 
						// retrieve either 4 bytes or 8 bytes depending on the pointer's size.

						for (ULONG i = 0; i < ArraySize; i++)
						{
							if (g_PointerSize == 4) 
							{
								ULONG temp = 0;

								CopyMemory(&temp, pEventData, sizeof(ULONG));
								wprintf(L"0x%x\n", temp);
							}
							else
							{
								ULONGLONG temp = 0;

								CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
								wprintf(L"0x%x\n", temp);
							}

							pEventData += g_PointerSize;
						}

						return pEventData;
					}
					if (_wcsicmp(L"Port", varQualifier.bstrVal) == 0)
					{
						USHORT temp = 0;

						VariantClear(&varQualifier);

						for (ULONG i = 0; i < ArraySize; i++)
						{
							CopyMemory(&temp, pEventData, sizeof(USHORT));
							wprintf(L"%hu\n", ntohs(temp));
							pEventData += sizeof(USHORT);
						}

						return pEventData;
					}
					else if (_wcsicmp(L"IPAddr", varQualifier.bstrVal) == 0 ||
						_wcsicmp(L"IPAddrV4", varQualifier.bstrVal) == 0)
					{
						ULONG temp = 0;

						VariantClear(&varQualifier);

						for (ULONG i = 0; i < ArraySize; i++)
						{
							CopyMemory(&temp, pEventData, sizeof(ULONG));

							wprintf(L"%d.%d.%d.%d\n", (temp >>  0) & 0xff,
								(temp >>  8) & 0xff,
								(temp >>  16) & 0xff,
								(temp >>  24) & 0xff);

							pEventData += sizeof(ULONG);
						}

						return pEventData;
					}
					else if (_wcsicmp(L"IPAddrV6", varQualifier.bstrVal) == 0)
					{
						// 						WCHAR IPv6AddressAsString[46];
						// 						IN6_ADDR IPv6Address;
						// 						PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;
						// 
						// 						VariantClear(&varQualifier);
						// 
						// 						fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
						// 							GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");
						// 
						// 						if (NULL == fnRtlIpv6AddressToString)
						// 						{
						// 							wprintf(L"GetProcAddress failed with %lu.\n", GetLastError());
						// 							return NULL;
						// 						}
						// 
						// 						for (ULONG i = 0; i < ArraySize; i++)
						// 						{
						// 							CopyMemory(&IPv6Address, pEventData, sizeof(IN6_ADDR));
						// 
						// 							fnRtlIpv6AddressToString(&IPv6Address, IPv6AddressAsString);
						// 
						// 							wprintf(L"%s\n", IPv6AddressAsString);
						// 
						// 							pEventData += sizeof(IN6_ADDR);
						// 						}

						return pEventData;
					}
					else if (_wcsicmp(L"Guid", varQualifier.bstrVal) == 0)
					{
						WCHAR szGuid[50];
						GUID Guid;

						VariantClear(&varQualifier);

						for (ULONG i = 0; i < ArraySize; i++)
						{
							CopyMemory(&Guid, (GUID*)pEventData, sizeof(GUID));

							StringFromGUID2(Guid, szGuid, sizeof(szGuid)-1);
							wprintf(L"%s\n", szGuid);

							pEventData += sizeof(GUID);
						}

						return pEventData;
					}
					else if (_wcsicmp(L"Sid", varQualifier.bstrVal) == 0)
					{
						// Get the user's security identifier and print the 
						// user's name and domain.

						SID* psid;
						DWORD cchUserSize = 0;
						DWORD cchDomainSize = 0;
						WCHAR* pUser = NULL;
						WCHAR* pDomain = NULL;
						SID_NAME_USE eNameUse;
						DWORD status = 0;
						ULONG temp = 0;
						USHORT CopyLength = 0;
						BYTE buffer[SECURITY_MAX_SID_SIZE];

						VariantClear(&varQualifier);

						for (ULONG i = 0; i < ArraySize; i++)
						{
							CopyMemory(&temp, pEventData, sizeof(ULONG));

							if (temp > 0)
							{
								// A property with the Sid extension is actually a 
								// TOKEN_USER structure followed by the SID. The size
								// of the TOKEN_USER structure differs depending on 
								// whether the events were generated on a 32-bit or 
								// 64-bit architecture. Also the structure is aligned
								// on an 8-byte boundary, so its size is 8 bytes on a
								// 32-bit computer and 16 bytes on a 64-bit computer.
								// Doubling the pointer size handles both cases.

								USHORT BytesToSid = g_PointerSize * 2;

								pEventData += BytesToSid;

								if (RemainingBytes - BytesToSid > SECURITY_MAX_SID_SIZE)
								{
									CopyLength = SECURITY_MAX_SID_SIZE;
								}
								else
								{
									CopyLength = RemainingBytes - BytesToSid;
								}

								CopyMemory(&buffer, pEventData, CopyLength);
								psid = (SID*)&buffer;

								LookupAccountSid(NULL, psid, pUser, &cchUserSize, pDomain, &cchDomainSize, &eNameUse);

								status = GetLastError();
								if (ERROR_INSUFFICIENT_BUFFER == status)
								{
									pUser = (WCHAR*)malloc(cchUserSize * sizeof(WCHAR));
									pDomain = (WCHAR*)malloc(cchDomainSize * sizeof(WCHAR));

									if (pUser && pDomain)
									{
										if (LookupAccountSid(NULL, psid, pUser, &cchUserSize, pDomain, &cchDomainSize, &eNameUse))
										{
											wprintf(L"%s\\%s\n", pDomain, pUser);
										}
										else
										{
											wprintf(L"Second LookupAccountSid failed with, %d\n", GetLastError());
										}
									}
									else
									{
										wprintf(L"Allocation error.\n");
									}

									if (pUser)
									{
										free(pUser);
										pUser = NULL;
									}

									if (pDomain)
									{
										free(pDomain);
										pDomain = NULL;
									}

									cchUserSize = 0;
									cchDomainSize = 0;
								}
								else if (ERROR_NONE_MAPPED == status)
								{
									wprintf(L"Unable to locate account for the specified SID\n");
								}
								else
								{
									wprintf(L"First LookupAccountSid failed with, %d\n", status);
								}

								//pEventData += SeLengthSid(psid);
							}
							else  // There is no SID
							{
								pEventData += sizeof(ULONG);
							}
						}

						return pEventData;
					}
					else
					{
						wprintf(L"Extension, %s, not supported.\n", varQualifier.bstrVal);
						VariantClear(&varQualifier);
						return NULL;
					}
				}
				else
				{
					wprintf(L"Object data type is missing Extension qualifier.\n");
					return NULL;
				}
			}

		default: 
			{
				wprintf(L"Unknown CIM type\n");
				return NULL;
			}

		} // switch
	}
}