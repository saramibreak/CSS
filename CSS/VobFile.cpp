#include "VobFile.h"
#include "CSSauth.h"
#include "CSSscramble.h"
#include "execScsiCmdforFileSystem.h"

//
// CDVDSession
//

CDVDSession::CDVDSession()
    : m_hDrive(INVALID_HANDLE_VALUE)
    , m_session(DVD_END_ALL_SESSIONS)
{
    ZeroMemory(m_SessionKey, sizeof(m_SessionKey));
    ZeroMemory(m_DiscKey, sizeof(m_DiscKey));
    ZeroMemory(m_TitleKey, sizeof(m_TitleKey));
}

CDVDSession::~CDVDSession()
{
    EndSession();
}

bool CDVDSession::Open(LPCTSTR path)
{
    Close();

    m_hDrive = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_READONLY|FILE_FLAG_SEQUENTIAL_SCAN, (HANDLE)NULL);
    if (m_hDrive == INVALID_HANDLE_VALUE) {
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
        if (!DeviceIoControl(m_hDrive, IOCTL_DVD_END_SESSION, &m_session, sizeof(m_session), NULL, 0, &BytesReturned, NULL)
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
    if (m_session != DVD_END_ALL_SESSIONS) {
        DWORD BytesReturned;
        DeviceIoControl(m_hDrive, IOCTL_DVD_END_SESSION, &m_session, sizeof(m_session), NULL, 0, &BytesReturned, NULL);
        m_session = DVD_END_ALL_SESSIONS;
    }
}

bool CDVDSession::Authenticate()
{
    if (m_session == DVD_END_ALL_SESSIONS) {
        return false;
    }

    BYTE Challenge[10], Key[10];

    for (BYTE i = 0; i < 10; i++) {
        Challenge[i] = i;
	}

    if (!SendKey(DvdChallengeKey, Challenge)) {
        return false;
    }

    if (!ReadKey(DvdBusKey1, Key)) {
        return false;
    }

    int varient = -1;

    for (int i = 31; i >= 0; i--) {
        BYTE KeyCheck[5];
        CSSkey1(i, Challenge, KeyCheck);
        if (!memcmp(KeyCheck, Key, 5)) {
            varient = i;
        }
    }

    if (!ReadKey(DvdChallengeKey, Challenge)) {
        return false;
    }

    CSSkey2(varient, Challenge, &Key[5]);

    if (!SendKey(DvdBusKey2, &Key[5])) {
        return false;
    }

    CSSbuskey(varient, Key, m_SessionKey);

    return true;
}

bool CDVDSession::GetDiscKey(FILE* fp)
{
    if (m_session == DVD_END_ALL_SESSIONS) {
        return false;
    }

    BYTE DiscKeys[2048];
    if (!ReadKey(DvdDiskKey, DiscKeys)) {
        return false;
    }
	OutputEncryptedDiscKey(fp, DiscKeys);

    for (int i = 0; i < g_nPlayerKeys; i++) {
        for (int j = 1; j < 409; j++) {
            BYTE DiscKey[6];
            memcpy(DiscKey, &DiscKeys[j * 5], 5);
            DiscKey[5] = 0;

            CSSdisckey(DiscKey, g_PlayerKeys[i]);

            BYTE Hash[6];
            memcpy(Hash, &DiscKeys[0], 5);
            Hash[5] = 0;

            CSSdisckey(Hash, DiscKey);

            if (!memcmp(Hash, DiscKey, 6)) {
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
    if (m_session == DVD_END_ALL_SESSIONS) {
        return false;
    }

    if (!ReadKey(DvdTitleKey, pKey, lba)) {
        return false;
    }

    if (!(pKey[0] | pKey[1] | pKey[2] | pKey[3] | pKey[4])) {
        return false;
    }

    pKey[5] = 0;

    CSStitlekey(pKey, m_DiscKey);

    return true;
}

static void Reverse(BYTE* d, BYTE* s, int len)
{
    if (d == s) {
        for (s += len - 1; d < s; d++, s--) {
            *d ^= *s, *s ^= *d, *d ^= *s;
        }
    } else {
        for (int i = 0; i < len; i++) {
            d[i] = s[len - 1 - i];
        }
    }
}

bool CDVDSession::SendKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData)
{
    CAutoVectorPtr<BYTE> key;
    DVD_COPY_PROTECT_KEY* pKey = nullptr;

    auto allocateKey = [&](ULONG len) {
        bool bSuccess = key.Allocate(len);
        if (bSuccess) {
            pKey = (DVD_COPY_PROTECT_KEY*)(BYTE*)key;
            pKey->KeyLength = len;
        }
        return bSuccess;
    };

    switch (KeyType) {
        case DvdChallengeKey:
            if (allocateKey(DVD_CHALLENGE_KEY_LENGTH)) {
                Reverse(pKey->KeyData, pKeyData, 10);
            }
            break;
        case DvdBusKey2:
            if (allocateKey(DVD_BUS_KEY_LENGTH)) {
                Reverse(pKey->KeyData, pKeyData, 5);
            }
            break;
        default:
            break;
    }

    if (!pKey) {
        return false;
    }

    pKey->SessionId = m_session;
    pKey->KeyType = KeyType;
    pKey->KeyFlags = 0;

    DWORD dwBytesReturned;
    return !!DeviceIoControl(m_hDrive, IOCTL_DVD_SEND_KEY, pKey, pKey->KeyLength, nullptr, 0, &dwBytesReturned, nullptr);
}

bool CDVDSession::ReadKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData, int lba)
{
    CAutoVectorPtr<BYTE> key;
    DVD_COPY_PROTECT_KEY* pKey = nullptr;

    auto allocateKey = [&](ULONG len) {
        bool bSuccess = key.Allocate(len);
        if (bSuccess) {
            pKey = (DVD_COPY_PROTECT_KEY*)(BYTE*)key;
            pKey->KeyLength = len;
        }
        return bSuccess;
    };

    switch (KeyType) {
        case DvdChallengeKey:
            if (allocateKey(DVD_CHALLENGE_KEY_LENGTH)) {
                pKey->Parameters.TitleOffset.QuadPart = 0;
            }
            break;
        case DvdBusKey1:
            if (allocateKey(DVD_BUS_KEY_LENGTH)) {
                pKey->Parameters.TitleOffset.QuadPart = 0;
            }
            break;
        case DvdDiskKey:
            if (allocateKey(DVD_DISK_KEY_LENGTH)) {
                pKey->Parameters.TitleOffset.QuadPart = 0;
            }
            break;
        case DvdTitleKey:
            if (allocateKey(DVD_TITLE_KEY_LENGTH)) {
                pKey->Parameters.TitleOffset.QuadPart = 2048i64 * lba;
            }
            break;
        default:
            break;
    }

    if (!pKey) {
        return false;
    }

    pKey->SessionId = m_session;
    pKey->KeyType = KeyType;
    pKey->KeyFlags = 0;

    DWORD dwBytesReturned;
    if (!DeviceIoControl(m_hDrive, IOCTL_DVD_READ_KEY, pKey, pKey->KeyLength, pKey, pKey->KeyLength, &dwBytesReturned, nullptr)) {
		OutputLastErrorNumAndString(_T(__FUNCTION__), __LINE__);
		fprintf(stderr, "-> LBA %d\n", lba);
		return false;
    }

    switch (KeyType) {
        case DvdChallengeKey:
            Reverse(pKeyData, pKey->KeyData, 10);
            break;
        case DvdBusKey1:
            Reverse(pKeyData, pKey->KeyData, 5);
            break;
        case DvdDiskKey:
            memcpy(pKeyData, pKey->KeyData, 2048);
            for (int i = 0; i < 2048/* / 5*/; i++) {
                pKeyData[i] ^= m_SessionKey[4 - (i % 5)];
            }
            break;
        case DvdTitleKey:
            memcpy(pKeyData, pKey->KeyData, 5);
            for (int i = 0; i < 5; i++) {
                pKeyData[i] ^= m_SessionKey[4 - (i % 5)];
            }
            break;
        default:
            break;
    }

    return true;
}

void CDVDSession::OutputEncryptedDiscKey(FILE* fp, LPBYTE DiscKeys)
{
	fprintf(fp, "AllDiscKeys ((40 bits per 1 key) * 409 keys)\n");
	for (INT i = 0; i < 409; i++) {
		fprintf(fp, "[%03d]: %02X %02X %02X %02X %02X"
			, i + 1, DiscKeys[5 * i], DiscKeys[5 * i + 1]
			, DiscKeys[5 * i + 2], DiscKeys[5 * i + 3], DiscKeys[5 * i + 4]);
		if (i % 4 == 0) {
			fprintf(fp, "\n");
		}
		else {
			fprintf(fp, " ");
		}
	}
}

void CDVDSession::OutputDecryptedDiscKey(FILE* fp)
{
	fprintf(fp, "PlayerKey[%d]: %02X %02X %02X %02X %02X\n"
		, m_PlayerKeyIdx, m_PlayerKey[0], m_PlayerKey[1], m_PlayerKey[2], m_PlayerKey[3], m_PlayerKey[4]);
	fprintf(fp, "DecryptedDiscKey[%03d]: %02X %02X %02X %02X %02X\n"
		, m_DiscKeyIdx, m_DiscKey[0], m_DiscKey[1], m_DiscKey[2], m_DiscKey[3], m_DiscKey[4]);
}

void CDVDSession::OutputTitleKey(FILE* fp, INT lba, CHAR* fname, BYTE* titleKey)
{
	fprintf(fp, "LBA: %7d, Filename: %s, TitleKey: %02X %02X %02X %02X %02X\n"
		, lba, fname, titleKey[0], titleKey[1], titleKey[2], titleKey[3], titleKey[4]);
}
