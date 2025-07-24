/*
 * Copyright 2020 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

 //---------------------------------------------------------------------------
 // Updater
 //---------------------------------------------------------------------------

#include "stdafx.h"
#include <winhttp.h>
#include "Updater.h"
#include "UpdateDialog.h"
#include "common/RunBrowser.h"
#include "SbieIni.h"
#include "UserSettings.h"
#define CRC_WITH_ADLER32
#include "common/crc.c"
#include "common/my_version.h"
#include "common/json/JSON.h"
#include "common/win32_ntddk.h"
#include "core/drv/api_defs.h"

#define UPDATE_INTERVAL (7 * 24 * 60 * 60)

//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


CUpdater *CUpdater::m_instance = NULL;


//---------------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------------


CUpdater::CUpdater()
{
	m_update_pending = false;

	//OSVERSIONINFOW m_osvi = { 0 };
	m_osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
	NTSTATUS(WINAPI *RtlGetVersion)(LPOSVERSIONINFOW);
	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL || !NT_SUCCESS(RtlGetVersion(&m_osvi)))
		GetVersionExW(&m_osvi);
}


//---------------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------------


CUpdater::~CUpdater()
{
}


//---------------------------------------------------------------------------
// GetInstance
//---------------------------------------------------------------------------


CUpdater &CUpdater::GetInstance()
{
	if (!m_instance)
		m_instance = new CUpdater();
	return *m_instance;
}


//---------------------------------------------------------------------------
// CheckUpdates
//---------------------------------------------------------------------------


bool CUpdater::CheckUpdates(CWnd *pParentWnd, bool bManual)
{
	if (m_update_pending)
		return false;

	ULONG ThreadId;
	ULONG_PTR *ThreadArgs = new ULONG_PTR[2];
	ThreadArgs[0] = (ULONG_PTR)pParentWnd->m_hWnd;
	ThreadArgs[1] = bManual ? 1 : 0;
	CreateThread(NULL, 0, UpdaterServiceThread, ThreadArgs, 0, &ThreadId);
	return true;
}


//---------------------------------------------------------------------------
// DownloadUpdateData
//---------------------------------------------------------------------------


BOOLEAN CUpdater::DownloadUpdateData(const WCHAR* Host, const WCHAR* Path, PSTR* pData, ULONG* pDataLength)
{
	BOOLEAN success = FALSE;

	PVOID SessionHandle = NULL;
	PVOID ConnectionHandle = NULL;
	PVOID RequestHandle = NULL;

	{
		SessionHandle = WinHttpOpen(NULL,
			m_osvi.dwMajorVersion >= 8 ? WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
		if (!SessionHandle)
			goto CleanupExit;

		if (m_osvi.dwMajorVersion >= 8) {
			ULONG Options = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
			WinHttpSetOption(SessionHandle, WINHTTP_OPTION_DECOMPRESSION, &Options, sizeof(Options));
		}
	}

	{
		ConnectionHandle = WinHttpConnect(SessionHandle, Host, 443, 0); // ssl port
		if (!ConnectionHandle)
			goto CleanupExit;
	}

	{
		ULONG httpFlags = WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH;
		RequestHandle = WinHttpOpenRequest(ConnectionHandle,
			NULL, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, httpFlags);

		if (!RequestHandle)
			goto CleanupExit;

		ULONG Options = WINHTTP_DISABLE_KEEP_ALIVE;
		WinHttpSetOption(RequestHandle, WINHTTP_OPTION_DISABLE_FEATURE, &Options, sizeof(Options));
	}

	if (!WinHttpSendRequest(RequestHandle, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
		goto CleanupExit;

	if (!WinHttpReceiveResponse(RequestHandle, NULL))
		goto CleanupExit;

	{
		PVOID result = NULL;
		ULONG allocatedLength;
		ULONG dataLength;
		ULONG returnLength;
		BYTE buffer[PAGE_SIZE];

		if (pData == NULL)
			goto CleanupExit;

		allocatedLength = sizeof(buffer);
		*pData = (PSTR)malloc(allocatedLength);
		dataLength = 0;

		while (WinHttpReadData(RequestHandle, buffer, PAGE_SIZE, &returnLength))
		{
			if (returnLength == 0)
				break;

			if (allocatedLength < dataLength + returnLength)
			{
				allocatedLength *= 2;
				*pData = (PSTR)realloc(*pData, allocatedLength);
			}

			memcpy(*pData + dataLength, buffer, returnLength);

			dataLength += returnLength;
		}

		if (allocatedLength < dataLength + 1)
		{
			allocatedLength++;
			*pData = (PSTR)realloc(*pData, allocatedLength);
		}

		// Ensure that the buffer is null-terminated.
		(*pData)[dataLength] = 0;

		if (pDataLength != NULL)
			*pDataLength = dataLength;
	}

	success = TRUE;

CleanupExit:
	if (RequestHandle)
		WinHttpCloseHandle(RequestHandle);
	if (ConnectionHandle)
		WinHttpCloseHandle(ConnectionHandle);
	if (SessionHandle)
		WinHttpCloseHandle(SessionHandle);

	return success;
}


//---------------------------------------------------------------------------
// GetJSONObjectSafe
//---------------------------------------------------------------------------


JSONObject GetJSONObjectSafe(const JSONObject& root, const std::wstring& key)
{
	auto I = root.find(key);
	if (I == root.end() || !I->second->IsObject())
		return JSONObject();
	return I->second->AsObject();
}


//---------------------------------------------------------------------------
// GetJSONStringSafe
//---------------------------------------------------------------------------


std::wstring GetJSONStringSafe(const JSONObject& root, const std::wstring& key, const std::wstring& default = L"")
{
	auto I = root.find(key);
	if (I == root.end() || !I->second->IsString())
		return default;
	return I->second->AsString();
}


//---------------------------------------------------------------------------
// QueryUpdateData
//---------------------------------------------------------------------------

extern "C" int LCIDToLocaleName(LCID Locale, LPWSTR lpName, int cchName, DWORD dwFlags);

BOOLEAN CUpdater::QueryUpdateData(UPDATER_DATA* Context)
{
	BOOLEAN success = FALSE;

	CString Path;

	char* jsonString = NULL;
	JSONValue* jsonObject = NULL;
	JSONObject jsonRoot;
	JSONObject release;
	JSONObject installer;

	wchar_t StrLang[16];
	LCIDToLocaleName(SbieDll_GetLanguage(NULL), StrLang, ARRAYSIZE(StrLang), 0);
	if (StrLang[2] == L'-') StrLang[2] = '_';

	Path.Format(L"/update.php?action=update&software=sandboxie&channel=stable&version=%S&system=windows-%d.%d.%d-%s&language=%s&auto=%s", 
		MY_VERSION_STRING, m_osvi.dwMajorVersion, m_osvi.dwMinorVersion, m_osvi.dwBuildNumber,
#ifdef _M_ARM64
		L"ARM64",
#elif _WIN64
		L"x86_64",
#else
		L"i386",
#endif
		StrLang, Context->Manual ? L"0" : L"1");

	if (!Context->Manual)
		Path.AppendFormat(L"&interval=%d", UPDATE_INTERVAL);

	CString update_key;
	//CSbieIni::GetInstance().GetText(_GlobalSettings, L"UpdateKey", update_key);

    WCHAR CertPath[MAX_PATH];
    SbieApi_GetHomePath(NULL, 0, CertPath, MAX_PATH);
    wcscat(CertPath, L"\\Certificate.dat");
	HANDLE hFile = CreateFile(CertPath, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		char CertData[0x1000];
		DWORD bytesRead = 0;
		if (ReadFile(hFile, CertData, sizeof(CertData), &bytesRead, NULL)) {
			CertData[bytesRead] = 0;

			CString sCertData = CString(CertData);
			int pos = sCertData.Find(L"UPDATEKEY:");
			if (pos != -1) {
				pos += 10;
				int end = sCertData.Find(L"\n", pos);
				if (end == -1) end = sCertData.GetLength();
				update_key = sCertData.Mid(pos, end - pos).Trim();
			}
		}
		CloseHandle(hFile);
	}

	Path += L"&update_key=" + update_key;

    QWORD RandID = 0;
    SbieApi_Call(API_GET_SECURE_PARAM, 3, L"RandID", (ULONG_PTR)&RandID, sizeof(RandID));
    if (RandID == 0) {
		srand(GetTickCount());
        RandID = QWORD(rand() & 0xFFFF) | (QWORD(rand() & 0xFFFF) << 16) | (QWORD(rand() & 0xFFFF) << 32) | (QWORD(rand() & 0xFFFF) << 48);
        SbieApi_Call(API_SET_SECURE_PARAM, 3, L"RandID", (ULONG_PTR)&RandID, sizeof(RandID));
    }

	CString Section;
    CString UserName;
    BOOL    IsAdmin;
	CSbieIni::GetInstance().GetUser(Section, UserName, IsAdmin);
	DWORD Hash = wcstoul(Section.Mid(13), NULL, 16);

	wchar_t sHash[26];
	wsprintf(sHash, L"%08X-%08X%08X", Hash, DWORD(RandID >> 32), DWORD(RandID));
	Path += L"&hash_key=" + CString(sHash);

	if (!DownloadUpdateData(L"sandboxie-plus.com", Path, &jsonString, NULL)) {
		Context->ErrorCode = GetLastError();
		goto CleanupExit;
	}

	jsonObject = JSON::Parse((const char*)jsonString);
	if (jsonObject == NULL || !jsonObject->IsObject()) {
		Context->ErrorCode = WEB_E_INVALID_JSON_STRING;
		goto CleanupExit;
	}

	jsonRoot = jsonObject->AsObject();

	Context->userMsg = GetJSONStringSafe(jsonRoot, L"userMsg").c_str();
	Context->infoUrl = GetJSONStringSafe(jsonRoot, L"infoUrl").c_str();

	release = GetJSONObjectSafe(jsonRoot, L"release");
	Context->updateMsg = GetJSONStringSafe(release, L"infoMsg").c_str();
	Context->updateUrl = GetJSONStringSafe(release, L"infoUrl").c_str();
	Context->version = GetJSONStringSafe(release, L"version").c_str();
	//Context->updated = (uint64_t)jsonRoot[L"updated"]->AsNumber();

	installer = GetJSONObjectSafe(release, L"installer");
	Context->downloadUrl = GetJSONStringSafe(installer, L"downloadUrl").c_str();

	success = TRUE;

CleanupExit:

	if (jsonString)
		free(jsonString);

	if (jsonObject)
		delete jsonObject;

	return success;
}


//---------------------------------------------------------------------------
// DownloadUpdate
//---------------------------------------------------------------------------


CString CUpdater::DownloadUpdate(const CString& downloadUrl)
{
	WCHAR TempDir[MAX_PATH + 1];
	if (GetTempPath(MAX_PATH, (LPWSTR)&TempDir) == 0)
		return L"";

	int hostPos = downloadUrl.Find(L"://") + 3;
	if(hostPos < 3)
		return L"";

	int pathPos = downloadUrl.Find(L"/", hostPos);
	if (pathPos < 0)
		return L"";

	CString Host = downloadUrl.Mid(hostPos, pathPos - hostPos);
	CString Path = downloadUrl.Mid(pathPos);

	int queryPos = downloadUrl.Find(L"?", pathPos);
	if (queryPos < 0)
		queryPos = downloadUrl.GetLength();

	CString Name = downloadUrl.Left(queryPos);
	Name = Name.Mid(Name.ReverseFind(L'/') + 1);
	if (Name.IsEmpty() || Name.Right(4).CompareNoCase(L".exe") != 0)
		Name = L"SandboxieInstall.exe";

	char* data = NULL;
	ULONG size = 0;

	if (!DownloadUpdateData(Host, Path, &data, &size)) 
		return L"";

	CString FilePath = TempDir + Name;

	ULONG bytesWriten = 0;
	HANDLE hFile = CreateFile(FilePath, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		//SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

		WriteFile(hFile, data, size, &bytesWriten, NULL);

		CloseHandle(hFile);
	}

	free(data);

	if(bytesWriten != size)
		return L"";

	return FilePath;
}


//---------------------------------------------------------------------------
// UpdaterServiceThread
//---------------------------------------------------------------------------


ULONG CUpdater::UpdaterServiceThread(void *lpParameter)
{
	// schedule next theck for in a week, except when the user choose never
	__int64 NextUpdateCheck;
	CUserSettings::GetInstance().GetNum64(_NextUpdateCheck, NextUpdateCheck, 0);
	if (NextUpdateCheck != -1)
		CUserSettings::GetInstance().SetNum64(_NextUpdateCheck, time(NULL) + UPDATE_INTERVAL);

	if (pContext->Manual)
		CMyApp::MsgBox(NULL, MSG_3629, MB_OK);
	m_instance->m_update_pending = false;

	return 0;
}
