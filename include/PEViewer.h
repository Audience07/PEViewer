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
VOID ReadField(const PE_CONTEXT& pe);
//将RVA转换为FOA
DWORD RVAToFOA(const PE_CONTEXT& pe, DWORD Address);
//关闭内存随机化
BOOL CloseAddressRandomisation(const PE_CONTEXT &pe);
//遍历导入表
VOID TraversImportTable(const PE_CONTEXT& pe);