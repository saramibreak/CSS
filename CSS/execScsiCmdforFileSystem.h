/**
 * Copyright 2011-2019 sarami
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#define DISC_RAW_READ_SIZE		(2048)
#define DIRECTORY_RECORD_SIZE	(65535)
#define MAX_FNAME_FOR_VOLUME (128)
#define MIN_LEN_DR (34)
#define MAKEUINT(a, b)      ((UINT)(((WORD)(((UINT_PTR)(a)) & 0xffff)) | ((UINT)((WORD)(((UINT_PTR)(b)) & 0xffff))) << 16))

#define FreeAndNull(lpBuf) \
{ \
	if (lpBuf) { \
		free(lpBuf); \
		lpBuf = NULL; \
	} \
}

#ifdef _DEBUG
extern CHAR logBufferA[DISC_RAW_READ_SIZE];
#define OutputDebugStringExA(str, ...) \
{ \
	_snprintf(logBufferA, DISC_RAW_READ_SIZE, str, ##__VA_ARGS__); \
	logBufferA[2047] = 0; \
	OutputDebugStringA(logBufferA); \
}
#define OutputErrorStringA(str, ...)	OutputDebugStringExA(str, ##__VA_ARGS__)
#else
#define OutputErrorStringA(str, ...)	fprintf(stderr, str, ##__VA_ARGS__);
#endif
#define OutputErrorString		OutputErrorStringA

typedef enum _PATH_TYPE {
	lType,
	mType
} PATH_TYPE, *PPATH_TYPE;

#pragma pack(push, sensedata, 1)
typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
	SCSI_PASS_THROUGH_DIRECT ScsiPassThroughDirect;
	SENSE_DATA SenseData;
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
#pragma pack(pop, sensedata)

typedef struct _DEVICE {
#ifdef _WIN32
	HANDLE hDevice;
#else
	int hDevice;
#endif
	SCSI_ADDRESS address;
	DWORD dwMaxTransferLength;
	DWORD dwTimeOutValue;
} DEVICE, *PDEVICE;

typedef struct _VOLUME_DESCRIPTOR {
	struct _ISO_9660 {
		UINT uiLogicalBlkCoef;
		UINT uiPathTblSize;
		UINT uiPathTblPos;
		UINT uiRootDataLen;
	} ISO_9660;
	struct _JOLIET {
		UINT uiLogicalBlkCoef;
		UINT uiPathTblSize;
		UINT uiPathTblPos;
		UINT uiRootDataLen;
	} JOLIET;
	BOOL bPathType; // use path table record
} VOLUME_DESCRIPTOR, *PVOLUME_DESCRIPTOR;

typedef struct _DIRECTORY_RECORD {
	UINT uiDirNameLen;
	UINT uiPosOfDir;
	UINT uiNumOfUpperDir;
	CHAR szDirName[MAX_FNAME_FOR_VOLUME];
	UINT uiDirSize;
} DIRECTORY_RECORD, *PDIRECTORY_RECORD;

typedef struct _VOB {
	CHAR fname[MAX_FNAME_FOR_VOLUME];
	INT lba;
	INT idx;
} VOB, *PVOB;

VOID OutputLastErrorNumAndString(
	LPCTSTR pszFuncName,
	LONG lLineNum
);

BOOL ReadDVDForFileSystem(
	PDEVICE pDevice,
	CDB::_READ12* cdb,
	LPBYTE lpBuf,
	PVOB pVOB
);

BOOL ScsiPassThroughDirect(
	PDEVICE pDevice,
	LPVOID lpCdb,
	BYTE byCdbLength,
	LPVOID pvBuffer,
	INT nDataDirection,
	DWORD dwBufferLength,
	LPBYTE byScsiStatus,
	LPCTSTR pszFuncName,
	LONG lLineNum
);
