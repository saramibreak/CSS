// Css.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "VobFile.h"


int main(int argc, CHAR* argv[])
{
	if (argc != 2 || strlen(argv[1]) != 1) {
		printf("Usage: CSS.exe <DriveLetter>\n");
		return 1;
	}
	CDVDSession session;
	_TCHAR szBuf[8] = { 0 };
	_sntprintf(szBuf, 8, _T("\\\\.\\%c:"), argv[1][0]);
	szBuf[7] = 0;
	bool bRet = session.Open(szBuf);
	if (!bRet) {
		return 1;
	}
	bRet = session.BeginSession();
	if (!bRet) {
		return 1;
	}
	bRet = session.Authenticate();
	if (!bRet) {
		return 1;
	}
	bRet = session.GetDiscKey();
	if (!bRet) {
		return 1;
	}
	session.OutputDiscKey();
	session.EndSession();
	session.Close();
	return 0;
}

