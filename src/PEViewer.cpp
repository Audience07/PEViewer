#define _CRT_SECURE_NO_WARNINGS
#include "../include/PEViewer.h"



PE_CONTEXT LoadFileToMemory(IN LPCSTR str) {
	PE_CONTEXT pe{};
	//读取文件
	FILE* File{ fopen(str, "rb") };
	if (!File) {
		std::cout << "[-]打开文件失败" << std::endl;
		return pe;
	}
	//把指针放在末尾,获取文件大小
	fseek(File, 0, SEEK_END);
	pe.FileSize = (SIZE_T)ftell(File);
	fseek(File, 0, SEEK_SET);

	//分配内存
	pe.pFileBuffer = malloc(pe.FileSize);
	if (!pe.pFileBuffer) {
		std::cout << "[-]分配内存失败" << std::endl;
		fclose(File);
		return pe;
	}
	
	//将文件读入内存
	fread(pe.pFileBuffer, pe.FileSize, 1, File);

	//给dos,nt指针赋值
	pe.pDos = (PIMAGE_DOS_HEADER)pe.pFileBuffer;
	pe.pNT = (PIMAGE_NT_HEADERS32)((char*)pe.pFileBuffer + pe.pDos->e_lfanew);

	//校验是否为pe文件
	if (pe.pDos->e_magic != IMAGE_DOS_SIGNATURE) return pe;
	if (pe.pNT->Signature != IMAGE_NT_SIGNATURE) return pe;
	pe.isVaild = true;
	fclose(File);
	return pe;
}





//判断是否为文件
BOOL check_path_win(const char* path) {
	DWORD dwAttrib = GetFileAttributesA(path);

	if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
		std::cout << "无效的路径" << std::endl;
		return FALSE;
	}

	if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
		std::cout << "请输入文件" << std::endl;
		return FALSE;
	}
	else {
		// 如果不是目录，且没有其他特殊标记（如设备文件），则视为文件
		return TRUE;
	}
}




void ReadField(const PE_CONTEXT& pe) {
	PIMAGE_FILE_HEADER pFileHeader{ &pe.pNT->FileHeader };
	PIMAGE_OPTIONAL_HEADER32 pPEHeader{ &pe.pNT->OptionalHeader };
	PIMAGE_SECTION_HEADER pSectionheader{ (PIMAGE_SECTION_HEADER)((BYTE*)pPEHeader + pFileHeader->SizeOfOptionalHeader) };
	//文件头和可选pe头
	std::cout << "------------------------------------DosHeader-----------------------------------------" << std::endl;
	std::cout << "[+]e_magic:0x" << std::hex << pe.pDos->e_magic << std::endl;
	std::cout << "------------------------------------Fileheader----------------------------------------" << std::endl;
	std::cout << "[+]Machine:0x" << std::hex << pFileHeader->Machine << std::endl;
	std::cout << "[+]NumberOfSections:" << pFileHeader->NumberOfSections << std::endl;
	std::cout << "[+]SizeOfOptionalHeader:0x" << std::hex << pFileHeader->SizeOfOptionalHeader << std::endl;
	std::cout << "[+]Megic:0x" << std::hex << pPEHeader->Magic << std::endl;
	std::cout << "[+]AddressOfEntryPoint:0x" << std::hex << pPEHeader->AddressOfEntryPoint << std::endl;
	std::cout << "[+]ImageBase:0x" << std::hex << pPEHeader->ImageBase << std::endl;
	std::cout << "[+]SectionAlignment:0x" << std::hex << pPEHeader->SectionAlignment << std::endl;
	std::cout << "[+]FileAlignment:0x" << std::hex << pPEHeader->FileAlignment << std::endl;
	std::cout << "[+]SizeOfImage:0x" << std::hex << pPEHeader->SizeOfImage << std::endl;
	std::cout << "[+]SizeOfHeaders:0x" << std::hex << pPEHeader->SizeOfHeaders << std::endl;
	//节表
	std::cout << "------------------------------------SectionTable--------------------------------------" << std::endl;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
		std::cout << pSectionheader[i].Name << ":" << std::endl;
		std::cout <<"[+]PhysicalAddress:0x" << pSectionheader[i].Misc.PhysicalAddress << std::endl;
		std::cout << "[+]VirtualSize:0x" << pSectionheader[i].Misc.VirtualSize << std::endl;
		std::cout << "[+]VirtualAddress:0x" << pSectionheader[i].VirtualAddress << std::endl;
		std::cout << "[+]SizeOfRawData:0x" << pSectionheader[i].SizeOfRawData << std::endl;
		std::cout << "[+]PointerToRawData:0x" << pSectionheader[i].PointerToRawData << std::endl;
		std::cout << "[+]Characteristics:0x" << pSectionheader[i].Characteristics << std::endl;
	}
}