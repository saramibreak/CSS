#pragma once

class CDVDSession
{
protected:
	HANDLE m_hDrive;

	DVD_SESSION_ID m_session;

	BYTE m_SessionKey[5];

	BYTE m_PlayerKey[6], m_DiscKey[6], m_TitleKey[6];
	INT m_PlayerKeyIdx, m_DiscKeyIdx;

public:
	CDVDSession();
	virtual ~CDVDSession();

	bool Open(LPCTSTR path);
	void Close();

	bool BeginSession();
	void EndSession();
	bool Authenticate();
	bool GetDiscKey(FILE* fp);
	bool GetTitleKey(int lba, BYTE* pKey);
	bool SendKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData);
	bool ReadKey(DVD_KEY_TYPE KeyType, BYTE* pKeyData, int lba = 0);

	void OutputEncryptedDiscKey(FILE* fp, LPBYTE DiscKeys);
	void OutputDecryptedDiscKey(FILE* fp);
	void OutputTitleKey(FILE* fp, INT lba, CHAR* fname, BYTE* titleKey);
};
