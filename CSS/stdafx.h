// stdafx.h : 標準のシステム インクルード ファイルのインクルード ファイル、または
// 参照回数が多く、かつあまり変更されない、プロジェクト専用のインクルード ファイル
// を記述します。
//

#pragma once

#include "targetver.h"

// TODO: プログラムに必要な追加ヘッダーをここで参照してください

#pragma warning(disable:4710 4711)
#pragma warning(push)
#pragma warning(disable:4191 4365 4668 4820 5039 5045)
#include <windows.h>
#include <atlbase.h>

// SPTI(needs Windows Driver Kit(wdk))
#include <ntddcdvd.h> // inc\api
#include <ntddscsi.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>
#undef _NTSCSI_USER_MODE_

#pragma warning(pop)
