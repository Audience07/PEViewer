#pragma once
#include <Windows.h>
#include <iostream>
#include <stdlib.h>

struct PE_CONTEXT {
	LPVOID pFileBuffer{nullptr};
	SIZE_T FileSize{};
	PIMAGE_DOS_HEADER pDos{nullptr};
	PIMAGE_NT_HEADERS pNT{nullptr};
	BOOL isVaild{FALSE};
};




//读取文件内存
PE_CONTEXT LoadFileToMemory(IN LPCSTR str);
//读取dos头关键字段
void ReadField(const PE_CONTEXT& pe);
//判断是否为文件
BOOL check_path_win(const char* path);