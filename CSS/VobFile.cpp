#include "VobFile.h"
#include "CSSauth.h"
#include "CSSscramble.h"

//
// CDVDSession
//

CDVDSession::CDVDSession()
	: m_session(DVD_END_ALL_SESSIONS)
	, m_hDrive(INVALID_HANDLE_VALUE)
{
}

CDVDSession::~CDVDSession()
{
	EndSession();
}

void CDVDSession::OutputLastErrorNumAndString(
	LPCTSTR pszFuncName,
	LONG lLineNum
) {
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

	fprintf(stderr, _T("[F:%s][L:%lu] GetLastError: %lu, %s\n"),
		pszFuncName, lLineNum, GetLastError(), (LPCTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
}

bool CDVDSession::Open(LPCTSTR path)
{
	Close();

	m_hDrive = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
						  OPEN_EXISTING, FILE_ATTRIBUTE_READONLY|FILE_FLAG_SEQUENTIAL_SCAN, (HANDLE)NULL);
	if(m_hDrive == INVALID_HANDLE_VALUE) {
		OutputLastErrorNumAndString(_T(__FUNCTION__), __LINE__);
		return false;
	}

	return true;
}

void CDVDSession::Close()
{
	if(m_hDrive != INVALID_HANDLE_VALUE) {
		CloseHandle(m_hDrive);
		m_hDrive = INVALID_HANDLE_VALUE;
	}
}

bool CDVDSession::BeginSession()
{
	EndSession();

	if(m_hDrive == INVALID_HANDLE_VALUE) {
		return false;
	}

	DWORD BytesReturned;
	if(!DeviceIoControl(m_hDrive, IOCTL_DVD_START_SESSION, NULL, 0, &m_session, sizeof(m_session), &BytesReturned, NULL)) {
		m_session = DVD_END_ALL_SESSIONS;
		if(!DeviceIoControl(m_hDrive, IOCTL_DVD_END_SESSION, &m_session, sizeof(m_session), NULL, 0, &BytesReturned, NULL)
				|| !DeviceIoControl(m_hDrive, IOCTL_DVD_START_SESSION, NULL, 0, &m_session, sizeof(m_session), &BytesReturned, NULL)) {
			Close();
			OutputLastErrorNumAndString(_T(__FUNCTION__), __LINE__);
			return false;
		}
	}

	return true;
}

void CDVDSession::EndSession()
{
	if(m_session != DVD_END_ALL_SESSIONS) {
		DWORD BytesReturned;
		DeviceIoControl(m_hDrive, IOCTL_DVD_END_SESSION, &m_session, sizeof(m_session), NULL, 0, &BytesReturned, NULL);
		m_session = DVD_END_ALL_SESSIONS;
	}
}

bool CDVDSession::Authenticate()
{
	if(m_session == DVD_END_ALL_SESSIONS) {
		return false;
	}

	BYTE Challenge[10], Key[10];

	for(int i = 0; i < 10; i++) {
		Challenge[i] = i;
	}

	if(!SendKey(DvdChallengeKey, Challenge)) {
		return false;
	}

	if(!ReadKey(DvdBusKey1, Key)) {
		return false;
	}

	int varient = -1;

	for(int i = 31; i >= 0; i--) {
		BYTE KeyCheck[5];
		CSSkey1(i, Challenge, KeyCheck);
		if(!memcmp(KeyCheck, Key, 5)) {
			varient = i;
		}
	}

	if(!ReadKey(DvdChallengeKey, Challenge)) {
		return false;
	}

	CSSkey2(varient, Challenge, &Key[5]);

	if(!SendKey(DvdBusKey2, &Key[5])) {
		return false;
	}

	CSSbuskey(varient, Key, m_SessionKey);

	return true;
}

bool CDVDSession::GetDiscKey()
{
	if(m_session == DVD_END_ALL_SESSIONS) {
		return false;
	}

	BYTE DiscKeys[2048];
	if(!ReadKey(DvdDiskKey, DiscKeys)) {
		return false;
	}
	memcpy(m_AllDiscKey, DiscKeys, sizeof(DiscKeys));

	for(int i = 0; i < g_nPlayerKeys; i++) {
		for(int j = 1; j < 409; j++) {
			BYTE DiscKey[6];
			memcpy(DiscKey, &DiscKeys[j*5], 5);
			DiscKey[5] = 0;

			CSSdisckey(DiscKey, g_PlayerKeys[i]);

			BYTE Hash[6];
			memcpy(Hash, &DiscKeys[0], 5);
			Hash[5] = 0;

			CSSdisckey(Hash, DiscKey);

			if(!memcmp(Hash, DiscKey, 6)) {
				memcpy(m_PlayerKey, g_PlayerKeys[i], 6);
				m_PlayerKeyIdx = i + 1;
				memcpy(m_DiscKey, DiscKey, 6);
				m_DiscKeyIdx = j + 1;
				return true;
			}
		}
	}

	return false;
}

bool CDVDSession::GetTitleKey(int lba, BYTE* pKey)
{
	if(m_session == DVD_END_ALL_SESSIONS) {
		return false;
	}

	if(!ReadKey(DvdTitleKey, pKey, lba)) {
		return false;
	}

	if(!(pKey[0]|pKey[1]|pKey[2]|pKey[3]|pKey[4])) {
		return false;
	}

	pKey[5] = 0;

	CSStitlekey(pKey, m_DiscKey);

	return true;
}

static void Reverse(BYTE* d, BYTE* s, int len)
{
	if(d == s) {
		for(s += len-1; d < s; d++, s--) {
			*d ^= *s, *s ^= *d, *d ^= *s;
		}
	} else {
		for(int i = 0; i < len; i++) {
			d[i] = s[len-1 - i];
		}
	}
}

bool CDVDSession::SendKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData)
{
	CAutoPtr<DVD_COPY_PROTECT_KEY> key;

	switch(KeyType) {
		case DvdChallengeKey:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_CHALLENGE_KEY_LENGTH]);
			key->KeyLength = DVD_CHALLENGE_KEY_LENGTH;
			Reverse(key->KeyData, pKeyData, 10);
			break;
		case DvdBusKey2:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_BUS_KEY_LENGTH]);
			key->KeyLength = DVD_BUS_KEY_LENGTH;
			Reverse(key->KeyData, pKeyData, 5);
			break;
		default:
			break;
	}

	if(!key) {
		return false;
	}

	key->SessionId = m_session;
	key->KeyType = KeyType;
	key->KeyFlags = 0;

	DWORD BytesReturned;
	return(!!DeviceIoControl(m_hDrive, IOCTL_DVD_SEND_KEY, key, key->KeyLength, NULL, 0, &BytesReturned, NULL));
}

bool CDVDSession::ReadKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData, int lba)
{
	CAutoPtr<DVD_COPY_PROTECT_KEY> key;

	switch(KeyType) {
		case DvdChallengeKey:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_CHALLENGE_KEY_LENGTH]);
			key->KeyLength = DVD_CHALLENGE_KEY_LENGTH;
			key->Parameters.TitleOffset.QuadPart = 0;
			break;
		case DvdBusKey1:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_BUS_KEY_LENGTH]);
			key->KeyLength = DVD_BUS_KEY_LENGTH;
			key->Parameters.TitleOffset.QuadPart = 0;
			break;
		case DvdDiskKey:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_DISK_KEY_LENGTH]);
			key->KeyLength = DVD_DISK_KEY_LENGTH;
			key->Parameters.TitleOffset.QuadPart = 0;
			break;
		case DvdTitleKey:
			key.Attach((DVD_COPY_PROTECT_KEY*)DNew BYTE[DVD_TITLE_KEY_LENGTH]);
			key->KeyLength = DVD_TITLE_KEY_LENGTH;
			key->Parameters.TitleOffset.QuadPart = 2048i64*lba;
			break;
		default:
			break;
	}

	if(!key) {
		return false;
	}

	key->SessionId = m_session;
	key->KeyType = KeyType;
	key->KeyFlags = 0;

	DWORD BytesReturned;
	if(!DeviceIoControl(m_hDrive, IOCTL_DVD_READ_KEY, key, key->KeyLength, key, key->KeyLength, &BytesReturned, NULL)) {
		OutputLastErrorNumAndString(_T(__FUNCTION__), __LINE__);
		return false;
	}

	switch(KeyType) {
		case DvdChallengeKey:
			Reverse(pKeyData, key->KeyData, 10);
			break;
		case DvdBusKey1:
			Reverse(pKeyData, key->KeyData, 5);
			break;
		case DvdDiskKey:
			memcpy(pKeyData, key->KeyData, 2048);
			for(int i = 0; i < 2048/5; i++) {
				pKeyData[i] ^= m_SessionKey[4-(i%5)];
			}
			break;
		case DvdTitleKey:
			memcpy(pKeyData, key->KeyData, 5);
			for(int i = 0; i < 5; i++) {
				pKeyData[i] ^= m_SessionKey[4-(i%5)];
			}
			break;
		default:
			break;
	}

	return true;
}

void CDVDSession::OutputDiscKey(CHAR* path)
{
	FILE* fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr, "Couldn't create %s\n", path);
		return;
	}
	fprintf(fp, "AllDiscKeys ((5 byte per 1 key) * 409 keys)\n");
	for (INT i = 0; i < 409; i++) {
		fprintf(fp, "[%03d]: %02X %02X %02X %02X %02X"
			, i + 1, m_AllDiscKey[5 * i], m_AllDiscKey[5 * i + 1]
			, m_AllDiscKey[5 * i + 2], m_AllDiscKey[5 * i + 3], m_AllDiscKey[5 * i + 4]);
		if (i % 4 == 0) {
			fprintf(fp, "\n");
		}
		else {
			fprintf(fp, " ");
		}
	}
	fprintf(fp, "PlayerKey[%d]: %02X %02X %02X %02X %02X\n"
		, m_PlayerKeyIdx, m_PlayerKey[0], m_PlayerKey[1], m_PlayerKey[2], m_PlayerKey[3], m_PlayerKey[4]);
	fprintf(fp, "DecryptedDiscKey[%03d]: %02X %02X %02X %02X %02X\n"
		, m_DiscKeyIdx, m_DiscKey[0], m_DiscKey[1], m_DiscKey[2], m_DiscKey[3], m_DiscKey[4]);
	fclose(fp);
}

void CDVDSession::OutputTitleKey()
{
	printf("TitleKey: %02x%02x%02x%02x%02x\n"
		, m_TitleKey[0], m_TitleKey[1], m_TitleKey[2], m_TitleKey[3], m_TitleKey[4]);
}
