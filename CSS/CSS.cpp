// Css.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "execScsiCmdforFileSystem.h"
#include "VobFile.h"

CHAR logBufferA[DISC_RAW_READ_SIZE];

int main(int argc, CHAR* argv[])
{
	if ((argc != 3) || strlen(argv[1]) != 1) {
		printf("Usage: CSS.exe <DriveLetter> <OutFile>\n");
		return 1;
	}

	_TCHAR szBuf[8] = { 0 };
	_sntprintf(szBuf, 8, _T("\\\\.\\%c:"), argv[1][0]);
	szBuf[7] = 0;
	DEVICE device = {};
	device.hDevice = CreateFile(szBuf, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	device.dwMaxTransferLength = 65536;
	device.dwTimeOutValue = 60;
	CDB::_READ12 cdb = {};
	cdb.OperationCode = SCSIOP_READ12;
	BYTE buf[2048] = {};
	VOB vob[256] = {};
	ReadDVDForFileSystem(&device, &cdb, buf, vob);
	CloseHandle(device.hDevice);

	CDVDSession session;
	bool bRet = session.Open(szBuf);
	if (!bRet) {
		fprintf(stderr, "Couldn't open %s\n",  szBuf);
		return 1;
	}

	bRet = session.BeginSession();
	if (!bRet) {
		fprintf(stderr, "Couldn't begin session\n");
		return 1;
	}
	bRet = session.Authenticate();
	if (!bRet) {
		fprintf(stderr, "Couldn't authenticate\n");
		return 1;
	}
	FILE* fp = fopen(argv[2], "w");
	if (!fp) {
		fprintf(stderr, "Couldn't create %s\n", argv[2]);
		return 1;
	}
	bRet = session.GetDiscKey(fp);
	if (!bRet) {
		fprintf(stderr, "Couldn't get disc Key\n");
		return 1;
	}
	session.OutputDecryptedDiscKey(fp);
	session.EndSession();

	BYTE titleKey[6] = {};
	for (INT i = 0; i < vob[0].idx; i++) {
		bRet = session.BeginSession();
		if (!bRet) {
			fprintf(stderr, "Couldn't begin session\n");
			return 1;
		}
		bRet = session.Authenticate();
		if (!bRet) {
			fprintf(stderr, "Couldn't authenticate\n");
			return 1;
		}
		bRet = session.GetTitleKey(vob[i].lba, titleKey);
		if (!bRet) {
			fprintf(fp, "LBA: %7d, Filename: %s, No TitleKey\n", vob[i].lba, vob[i].fname);
		}
		else {
			session.OutputTitleKey(fp, vob[i].lba, vob[i].fname, titleKey);
		}
		session.EndSession();
	}
	fclose(fp);

	session.Close();
	return 0;
}

