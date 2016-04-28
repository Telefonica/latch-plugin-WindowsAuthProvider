#include <Windows.h>
#include <subauth.h>
#include <string>

#include "latch.h"

#define LOG_FILE L"C:\\LatchAuthPackage.log"
#define CA_FILE_NAME "latchCA.pem"

const LPCWSTR RegistryMainPath = TEXT("SOFTWARE\\ElevenPaths\\LatchSubauthPackage");

static enum LatchStatus
{
	OPEN,
	CLOSED,
	UNKNOWN
};

static void WriteLog(__in LPWSTR text);
static void WriteLog(__in char* text);
static NTSTATUS GetCustomResponseForUserStatus(__in LPCWSTR registryKeyUserPath, LatchStatus latchStatus);


static LatchStatus QueryLatchStatus(const char* accountId, const char* operationId) {
	char *s, *response;
	LatchStatus status = LatchStatus::UNKNOWN;

	response = Latch::operationStatus(accountId, operationId);
	s = response;

	if (s != NULL && s[0] == '{') {
		s = strstr(s, "\"data\"");
		if (s != NULL) {
			s = strstr(s, operationId);
			if (s != NULL) {
				s = strstr(s, "\"status\"");
				if (s != NULL) {
					s = strstr(s, ":");
					if (s != NULL) {
						if (strncmp(s, ":\"on\"", 5) == 0) {
							status = LatchStatus::OPEN;
						}
						else if (strncmp(s, ":\"off\"", 6) == 0) {
							status = LatchStatus::CLOSED;
						}
					}
				}
			}
		}
	}

	free(response);

	return status;
}


static bool GetValueFromRegistry(__in LPCWSTR keyPath, __in LPCWSTR keyName, __in size_t destinationSize, __out char* destination)
{
	DWORD lpType = REG_SZ;
	HKEY hKey = 0;
	WCHAR lpData[1024];
	DWORD length = 1024;
	size_t numCharsConverted;

	memset(destination, 0, destinationSize);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hKey, keyName, NULL, &lpType, (LPBYTE)&lpData, &length) == ERROR_SUCCESS) {
			wcstombs_s(&numCharsConverted, destination, destinationSize, lpData, _TRUNCATE);
			RegCloseKey(hKey);
			return true;
		}
	}

	return false;
}

static bool GetDWORDValueFromRegistry(__in LPCWSTR keyPath, __in LPCWSTR keyName, __in size_t destinationSize, __out DWORD* destination)
{
	DWORD lpType = REG_DWORD;
	HKEY hKey = 0;
	DWORD length = sizeof(DWORD);
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hKey, keyName, NULL, &lpType, (LPBYTE)destination, &length) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return true;
		}
	}

	return false;
}


char CAFilePath[MAX_PATH];

void SetLatchCAFile() {
	char moduleFile[MAX_PATH];
	TCHAR moduleFileW[MAX_PATH];
	GetModuleFileName(NULL, moduleFileW, MAX_PATH);
	wcstombs_s(NULL, moduleFile, MAX_PATH, moduleFileW, _TRUNCATE);

	char* lastSlash = strrchr(moduleFile, '\\');
	strncpy_s(CAFilePath, moduleFile, (lastSlash - moduleFile) + 1);
	strcat_s(CAFilePath, MAX_PATH, "latchCA.pem");

	Latch::setTLSCAFile(CAFilePath);
}

/*++

Routine Description:

The subauthentication routine does client/server specific authentication
of a user. The credentials of the user are passed in addition to all the
information from SAM defining the user. This routine decides whether to
let the user log on.


Arguments:

LogonLevel -- Specifies the level of information given in
LogonInformation.

LogonInformation -- Specifies the description for the user
logging on.  The LogonDomainName field should be ignored.

Flags - Flags describing the circumstances of the logon.

MSV1_0_PASSTHRU -- This is a PassThru authenication.  (i.e., the
user isn't connecting to this machine.)
MSV1_0_GUEST_LOGON -- This is a retry of the logon using the GUEST
user account.

UserAll -- The description of the user as returned from SAM.

WhichFields -- Returns which fields from UserAllInfo are to be written
back to SAM.  The fields will only be written if MSV returns success
to it's caller.  Only the following bits are valid.

USER_ALL_PARAMETERS - Write UserAllInfo->Parameters back to SAM.  If
the size of the buffer is changed, Msv1_0SubAuthenticationRoutine
must delete the old buffer using MIDL_user_free() and reallocate the
buffer using MIDL_user_allocate().

UserFlags -- Returns UserFlags to be returned from LsaLogonUser in the
LogonProfile.  The following bits are currently defined:


LOGON_GUEST -- This was a guest logon
LOGON_NOENCRYPTION -- The caller didn't specify encrypted credentials

SubAuthentication packages should restrict themselves to returning
bits in the high order byte of UserFlags.  However, this convention
isn't enforced giving the SubAuthentication package more flexibility.

Authoritative -- Returns whether the status returned is an
authoritative status which should be returned to the original
caller.  If not, this logon request may be tried again on another
domain controller.  This parameter is returned regardless of the
status code.

LogoffTime - Receives the time at which the user should log off the
system.  This time is specified as a GMT relative NT system time.

KickoffTime - Receives the time at which the user should be kicked
off the system. This time is specified as a GMT relative system
time.  Specify, a full scale positive number if the user isn't to
be kicked off.

Return Value:

STATUS_SUCCESS: if there was no error.

STATUS_NO_SUCH_USER: The specified user has no account.
STATUS_WRONG_PASSWORD: The password was invalid.

STATUS_INVALID_INFO_CLASS: LogonLevel is invalid.
STATUS_ACCOUNT_LOCKED_OUT: The account is locked out
STATUS_ACCOUNT_DISABLED: The account is disabled
STATUS_ACCOUNT_EXPIRED: The account has expired.
STATUS_PASSWORD_MUST_CHANGE: Account is marked as Password must change
on next logon.
STATUS_PASSWORD_EXPIRED: The Password is expired.
STATUS_INVALID_LOGON_HOURS - The user is not authorized to log on at
this time.
STATUS_INVALID_WORKSTATION - The user is not authorized to log on to
the specified workstation.

--*/

NTSTATUS NTAPI Msv1_0SubAuthenticationRoutine(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime)
{
	WriteLog(L"Entering subauth module...\r\n");

	char appId[256];
	char secret[256];
	char operationId[256];
	char accountId[256];
	wchar_t userName[256];

	DWORD proxyPort = 80;
	char proxy[256];
	char proxyCredentials[256];

	memset(appId, 0, 256);
	memset(secret, 0, 256);
	memset(operationId, 0, 256);
	memset(accountId, 0, 256);
	memset(userName, 0, 256);

	memset(proxy, 0, 256);
	memset(proxyCredentials, 0, 256);

	if (LogoffTime) {
		LogoffTime->HighPart = 0x7FFFFFFF;
		LogoffTime->LowPart = 0xFFFFFFFF;
	}

	if (KickoffTime) {
		KickoffTime->HighPart = 0x7FFFFFFF;
		KickoffTime->LowPart = 0xFFFFFFFF;
	}

	if (GetValueFromRegistry(RegistryMainPath, TEXT("AppId"), 256, appId) &&
		GetValueFromRegistry(RegistryMainPath, TEXT("Secret"), 256, secret) &&
		GetValueFromRegistry(RegistryMainPath, TEXT("OperationId"), 256, operationId) &&
		strlen(appId) == 20 && strlen(secret) == 40 && strlen(operationId) == 20) {

		memcpy(userName, UserAll->UserName.Buffer, UserAll->UserName.Length);

		std::wstring userPath(RegistryMainPath);
		std::wstring user(userName);
		userPath += L"\\" + user;

		if (userName != NULL && GetValueFromRegistry(userPath.c_str(), TEXT("AccountId"), 256, accountId) && strlen(accountId) == 64) {

			if (GetValueFromRegistry(RegistryMainPath, TEXT("Proxy"), 256, proxy)) {
				GetDWORDValueFromRegistry(RegistryMainPath, TEXT("ProxyPort"), sizeof(DWORD), &proxyPort);

				Latch::setProxy(proxy);
				Latch::setProxyPort(proxyPort);
			}
			
			if (GetValueFromRegistry(RegistryMainPath, TEXT("ProxyCredentials"), 256, proxyCredentials)) {
				Latch::setProxyCredentials(proxyCredentials);
			}

			//Latch::setHost("http://testpath2.11paths.com");
			Latch::init(appId, secret);
			SetLatchCAFile();

			LatchStatus status = QueryLatchStatus(accountId, operationId);

			return GetCustomResponseForUserStatus(userPath.c_str(), status);
		}
		else {
			WriteLog(L"Error: Latch AccountId not found for current user.\r\n");
		}
	}
	else {
		WriteLog(L"Error: Latch API not configured.\r\n");
	}

	return STATUS_SUCCESS;
}

static LPCWSTR GetRegistryKeyForStatus(LatchStatus latchStatus) {
	switch (latchStatus) {
	case OPEN:
		return TEXT("LatchUnlocked");
	case CLOSED:
		return TEXT("LatchLocked");
	default:
		return TEXT("LatchUnknown");
	}
}

static NTSTATUS GetDefaultResponseForStatus(LatchStatus latchStatus) {
	switch (latchStatus) {
	case OPEN:
		return STATUS_SUCCESS;
	case CLOSED:
		return STATUS_ACCOUNT_LOCKED_OUT;
	default:
		return STATUS_SUCCESS;
	}
}


static NTSTATUS ParseResponse(char* response, NTSTATUS defaultResponse) {
	if (strcmp(response, "Success") == 0) {
		return STATUS_SUCCESS;
	}
	else if (strcmp(response, "Locked") == 0) {
		return STATUS_ACCOUNT_LOCKED_OUT;
	}
	else if (strcmp(response, "Disabled") == 0) {
		return STATUS_ACCOUNT_DISABLED;
	}
	else if (strcmp(response, "WrongPassword") == 0) {
		return STATUS_WRONG_PASSWORD;
	}
	else {
		return defaultResponse;
	}
}

static NTSTATUS GetCustomResponseForUserStatus(__in LPCWSTR registryKeyUserPath, LatchStatus latchStatus) {
	char response[256];
	memset(response, 0, 256);

	GetValueFromRegistry(registryKeyUserPath, GetRegistryKeyForStatus(latchStatus), 256, response);



	return ParseResponse(response, GetDefaultResponseForStatus(latchStatus));
}

NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime)
{
#ifdef ActiveDirectoryVersion
	return Msv1_0SubAuthenticationRoutine(LogonLevel, LogonInformation, Flags, UserAll, WhichFields, UserFlags, Authoritative, LogoffTime, KickoffTime);
#else
	if (Flags != MSV1_0_PASSTHRU) 	{
		return Msv1_0SubAuthenticationRoutine(LogonLevel, LogonInformation, Flags, UserAll, WhichFields, UserFlags, Authoritative, LogoffTime, KickoffTime);
	}
	else {
		if (LogoffTime) {
			LogoffTime->HighPart = 0x7FFFFFFF;
			LogoffTime->LowPart = 0xFFFFFFFF;
		}
		if (KickoffTime) {
			KickoffTime->HighPart = 0x7FFFFFFF;
			KickoffTime->LowPart = 0xFFFFFFFF;
		}
		return STATUS_SUCCESS;
	}
#endif
}


//static void WriteLog(__in char* text) {
//	size_t buffer_size = 256;
//	wchar_t wtext[256];
//	mbstowcs_s(&buffer_size, wtext, buffer_size, text, buffer_size);
//	LPWSTR ptr = wtext;
//	WriteLog(wtext);
//}

static void WriteLog(__in LPWSTR text) {
	/*
	HANDLE file;
	DWORD numBytesWritten;

	file = CreateFile(LOG_FILE, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (file != INVALID_HANDLE_VALUE) {
		SetFilePointer(file, 0, NULL, FILE_END);
		WriteFile(file, text, (lstrlen(text) * sizeof(WCHAR)), &numBytesWritten, NULL);
		CloseHandle(file);
	}
	*/
}
