#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "beacon.h"
#include "Iads.h"

#define S_ADS_NOMORE_ROWS                _HRESULT_TYPEDEF_(0x00005012L)
#define S_ADS_NOMORE_COLUMNS             _HRESULT_TYPEDEF_(0x00005013L)

WINBASEAPI BOOL WINAPI KERNEL32$GetComputerNameExW(COMPUTER_NAME_FORMAT,LPWSTR,	LPDWORD);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR lpLibFileName);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToLocalFileTime(const FILETIME*, LPFILETIME);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPFILETIME);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

WINBASEAPI HRESULT WINAPI OLE32$CoInitialize(LPVOID pvReserved);
WINBASEAPI void WINAPI OLE32$CoUninitialize();

WINBASEAPI INT WINAPI OLEAUT32$SystemTimeToVariantTime(LPSYSTEMTIME, DOUBLE*);
WINBASEAPI HRESULT WINAPI OLEAUT32$VariantChangeType(VARIANTARG* ,const VARIANTARG* ,USHORT ,VARTYPE );
WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANT*);
WINBASEAPI void WINAPI OLEAUT32$VariantInit(VARIANT*);


WINBASEAPI wchar_t* __cdecl MSVCRT$wcscat(wchar_t* dest, const wchar_t* src);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscpy(wchar_t* dest, const wchar_t* src);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t* wcs1, const wchar_t* wcs2);

WINBASEAPI BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINBASEAPI BOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,LPBOOL lpbDaclPresent, PACL* pDacl,LPBOOL lpbDaclDefaulted);
WINBASEAPI BOOL WINAPI ADVAPI32$GetAce(PACL pAcl,DWORD dwAceIndex, LPVOID* pAce);

typedef HRESULT(WINAPI* _ADsOpenObject)(LPCWSTR lpszPathName, LPCWSTR lpszUserName,LPCWSTR lpszPassword, DWORD dwReserved,REFIID riid,void** ppObject);
typedef BOOL(WINAPI* _FreeADsMem)(LPVOID);

BOOL GetCurrentDomain(wchar_t* pPath)
{
	wchar_t domain[50] = L"";
	DWORD dwDomainSize = sizeof(domain);
	//ComputerNameDnsDomain = 2
	BOOL success = KERNEL32$GetComputerNameExW(2, domain, &dwDomainSize);
	if (!success)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error GetComputerNameExW : %d\n", KERNEL32$GetLastError());
		return FALSE;
	}

	MSVCRT$wcscat(pPath, domain);

	return TRUE;
}
//REF: https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
void MapSidToAcct(PSID pSid, formatp* obj)
{
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	SID_NAME_USE eUse = 8; //SidTypeUnknown
	HANDLE hFile;
	PSECURITY_DESCRIPTOR pSD = NULL;

	// First call to LookupAccountSid to get the buffer sizes.
	bRtnBool = ADVAPI32$LookupAccountSidW(NULL, pSid, AcctName, (LPDWORD)&dwAcctName, DomainName, (LPDWORD)&dwDomainName, &eUse);

	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwAcctName);
	DomainName = (LPTSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwDomainName);

	// Second call to LookupAccountSid to get the account name.
	bRtnBool = ADVAPI32$LookupAccountSidW(NULL, pSid, AcctName, (LPDWORD)&dwAcctName, DomainName, (LPDWORD)&dwDomainName, &eUse);
	// Check GetLastError for LookupAccountSid error condition.
	if (bRtnBool == FALSE) {
		DWORD dwErrorCode = 0;

		dwErrorCode = KERNEL32$GetLastError();

		if (dwErrorCode == ERROR_NONE_MAPPED)
			BeaconPrintf(CALLBACK_ERROR,"Account owner not found for specified SID.\n");
		else
			BeaconPrintf(CALLBACK_OUTPUT,"Error in LookupAccountSid.\n");
		return;

	}

	BeaconFormatPrintf(obj,"\t%ls\\%ls\n", DomainName, AcctName);

	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, DomainName);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, AcctName);

}

VOID LdapSearch(wchar_t* myFilter, wchar_t* lpszPathName)
{

	
	HRESULT hr = S_OK; 
	ADS_SEARCH_COLUMN col; 
	// Can add support for these later
	LPWSTR szUsername = NULL; 
	LPWSTR szPassword = NULL; 

	IDirectorySearch* pDSSearch = NULL;

	ADS_SEARCH_HANDLE hSearch;
	DWORD dwCount = 0;
	unsigned int i = 0;

	LPWSTR pColumn;
	FILETIME filetime;
	LARGE_INTEGER liValue;
	SYSTEMTIME systemtime;
	DATE date;
	VARIANT varDate;
	OLEAUT32$VariantInit(&varDate);

	//Initialize beaconformat
	formatp obj;
	int len = 2048;
	BeaconFormatAlloc(&obj, len);

	// Initialize COM.
	OLE32$CoInitialize(0);

	HMODULE hActiveds = KERNEL32$LoadLibraryW(L"Activeds.dll");
	_ADsOpenObject pADsOpenObject = (_ADsOpenObject)GetProcAddress(hActiveds, "ADsOpenObject");
	_FreeADsMem pFreeADsMem = (_FreeADsMem)GetProcAddress(hActiveds, "FreeADsMem");

	// Open a connection with server.
	static GUID xIID_IDirectorySearch = { 0x109ba8ec, 0x92f0, 0x11d0, {0xa7, 0x90, 0x00, 0xc0, 0x4f, 0xd8, 0xd5, 0xa8} };
	hr = pADsOpenObject((LPCWSTR)lpszPathName, szUsername, szPassword, ADS_SECURE_AUTHENTICATION, &xIID_IDirectorySearch, (void**)&pDSSearch);

	if (!SUCCEEDED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR,"ADsOpenObject failed\n");
		goto DONE;
	}

	//Search specific attributes
	pDSSearch->lpVtbl->ExecuteSearch(pDSSearch, (LPWSTR)myFilter, NULL, (DWORD)-1, &hSearch);

	if (hSearch == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR,"Failed execute search\n");
		goto DONE;
	}

	while (pDSSearch->lpVtbl->GetNextRow(pDSSearch, hSearch) != S_ADS_NOMORE_ROWS)
	{
		while (pDSSearch->lpVtbl->GetNextColumnName(pDSSearch, hSearch, &pColumn) != S_ADS_NOMORE_COLUMNS)
		{
			hr = pDSSearch->lpVtbl->GetColumn(pDSSearch, hSearch, pColumn, &col);
			if (SUCCEEDED(hr))
			{

				if (col.dwADsType == ADSTYPE_PATH)
				{
					for (i = 0; i < col.dwNumValues; i++)
					{
						BeaconFormatPrintf(&obj,"%ls : %ls\n", pColumn, col.pADsValues->CaseIgnoreString);
					}
				}
				if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR)
				{
					for (i = 0; i < col.dwNumValues; i++)
					{
						ADS_NT_SECURITY_DESCRIPTOR sec = col.pADsValues[i].SecurityDescriptor;

						BOOL bDaclPresent = SE_DACL_PRESENT;
						BOOL bDaclDefaulted = SE_DACL_DEFAULTED;
						PACL pDacl = NULL;
						LPVOID pAce;
						ACCESS_ALLOWED_ACE* pAceBuffer;
						PSID pSid = NULL;
						wchar_t* accountName = NULL;
						ADVAPI32$GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sec.lpValue, &bDaclPresent, &pDacl, &bDaclDefaulted);
						if (bDaclPresent)
						{
							BeaconFormatPrintf(&obj,"[*]%ls: \n", pColumn);
							for (i = 0; i < pDacl->AceCount; i++)
							{
								ADVAPI32$GetAce(pDacl, i, &pAce);

								pAceBuffer = (ACCESS_ALLOWED_ACE*)pAce;
								pSid = (PSID)&pAceBuffer->SidStart;

								MapSidToAcct(pSid, &obj);



							}
						}

					}
				}

				if (col.dwADsType == ADSTYPE_BOOLEAN)
				{
					BOOL dwBool;
					const wchar_t* pBool = NULL;
					for (i = 0; i < col.dwNumValues; i++)
					{
						dwBool = col.pADsValues[i].Boolean;
						pBool = dwBool ? L"TRUE" : L"FALSE";
						BeaconFormatPrintf(&obj,"[*]%ls : %ls\n", pColumn, pBool);

					}

				}

				if (col.dwADsType == ADSTYPE_DN_STRING)
				{
					for (i = 0; i < col.dwNumValues; i++)
					{
						BeaconFormatPrintf(&obj,"[*]%ls : %ls\n", pColumn, col.pADsValues[i].DNString);

					}

				}
				if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING)
				{
					BeaconFormatPrintf(&obj,"[*]%ls : %ls\n", pColumn, col.pADsValues->CaseIgnoreString);
				}

				if (col.dwADsType == ADSTYPE_LARGE_INTEGER)
				{
					for (unsigned int x = 0; x < col.dwNumValues; x++)
					{
						liValue = col.pADsValues[x].LargeInteger;
						filetime.dwLowDateTime = liValue.LowPart;
						filetime.dwHighDateTime = liValue.HighPart;
						if ((filetime.dwHighDateTime == 0) && (filetime.dwLowDateTime == 0))
						{
							continue;
						}
						else
						{

							if (filetime.dwLowDateTime == -1)
							{
								BeaconFormatPrintf(&obj,"[*]%ls : Never Expires.\n", pColumn);
							}
							else
							{
								if (KERNEL32$FileTimeToLocalFileTime(&filetime, &filetime) != 0)
								{
									if (KERNEL32$FileTimeToSystemTime(&filetime, &systemtime) != 0)
									{
										if (OLEAUT32$SystemTimeToVariantTime(&systemtime, &date) != 0)
										{
											varDate.vt = VT_DATE;
											varDate.date = date;
											OLEAUT32$VariantChangeType(&varDate, &varDate, VARIANT_NOVALUEPROP, VT_BSTR);
											BeaconFormatPrintf(&obj,"[*]%ls : %ls\n", pColumn, (wchar_t*)varDate.bstrVal);

											OLEAUT32$VariantClear(&varDate);
										}
									}

								}
							}
						}

					}

				}
				pDSSearch->lpVtbl->FreeColumn(pDSSearch, &col);

			}


			pFreeADsMem(pColumn);
		}
		BeaconFormatPrintf(&obj,"\n\n");
	}
	pDSSearch->lpVtbl->CloseSearchHandle(pDSSearch, hSearch);
	int outSize = 0;
	char* dataOut = BeaconFormatToString(&obj, &outSize);
	BeaconOutput(CALLBACK_OUTPUT, dataOut, outSize);

DONE:
	if (pDSSearch)
		pDSSearch->lpVtbl->Release(pDSSearch);
	OLE32$CoUninitialize();
	BeaconFormatFree(&obj);

	return;
}

VOID FindDelegation(wchar_t* domain, int type)
{

	wchar_t path[50] = L"";
	MSVCRT$wcscpy(path, L"LDAP://");
	wchar_t* myFilter = L"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
	wchar_t* myFilter2 = L"(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
	wchar_t* myFilter3 = L"(&(msDS-AllowedToDelegateTo=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
	wchar_t* myFilter4 = L"(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
	
	if (MSVCRT$wcscmp(domain, L"local") == 0)
	{
		BOOL success = GetCurrentDomain(&path);
		if (!success)
			return;
	}
	else
	{
		MSVCRT$wcscat(path, domain);
	}

	if (type == 1)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find Contrained Delegation...\n\n");
		LdapSearch(myFilter3, path);
	}
	else if (type == 2)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find Contrained Delegation w/ Protocol Transition...\n\n");
		LdapSearch(myFilter2, path);
	}
	else if (type == 3)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Finding Unconstrained Delegation...\n\n");
		LdapSearch(myFilter, path);
	}
	else if (type == 4)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find RBCD...\n\n");
		LdapSearch(myFilter4, path);
	}
	else if (type == 5)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Finding Unconstrained Delegation...\n\n");
		LdapSearch(myFilter, path);

		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find Contrained Delegation w/ Protocol Transition...\n\n");
		LdapSearch(myFilter2, path);

		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find Contrained Delegation...\n\n");
		LdapSearch(myFilter3, path);

		BeaconPrintf(CALLBACK_OUTPUT, "\n[+]Find RBCD...\n\n");
		LdapSearch(myFilter4, path);
	}




}

void go(char* args, int length) {

	datap parser;
	int type;
	wchar_t* domain = NULL;
	BeaconDataParse(&parser, args, length);

	type = BeaconDataInt(&parser);
	domain = BeaconDataExtract(&parser, NULL);
	
	FindDelegation(domain, type);
	BeaconPrintf(CALLBACK_OUTPUT, "[*] Complete!\n");
}
