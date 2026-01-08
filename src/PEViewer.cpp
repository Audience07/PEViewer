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



VOID ReadField(const PE_CONTEXT& pe) {
	PIMAGE_FILE_HEADER pFileHeader{ &pe.pNT->FileHeader };
	PIMAGE_OPTIONAL_HEADER32 pPEHeader{ &pe.pNT->OptionalHeader };
	PIMAGE_SECTION_HEADER pSectionTable{ (PIMAGE_SECTION_HEADER)((BYTE*)pPEHeader + pFileHeader->SizeOfOptionalHeader) };
	//文件头和可选pe头
	std::cout << "------------------------------------DosHeader-----------------------------------------" << std::endl;
	std::cout << "[+]e_magic:0x" << std::hex << pe.pDos->e_magic << std::endl;
	std::cout << "------------------------------------FileHeader----------------------------------------" << std::endl;
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
		std::cout << pSectionTable[i].Name << ":" << std::endl;
		std::cout <<"[+]PhysicalAddress:0x" << pSectionTable[i].Misc.PhysicalAddress << std::endl;
		std::cout << "[+]VirtualSize:0x" << pSectionTable[i].Misc.VirtualSize << std::endl;
		std::cout << "[+]VirtualAddress:0x" << pSectionTable[i].VirtualAddress << std::endl;
		std::cout << "[+]SizeOfRawData:0x" << pSectionTable[i].SizeOfRawData << std::endl;
		std::cout << "[+]PointerToRawData:0x" << pSectionTable[i].PointerToRawData << std::endl;
		std::cout << "[+]Characteristics:0x" << pSectionTable[i].Characteristics << std::endl;
	}
}

//内存地址转外存地址（内存和外存对齐不一样，在内存中相比硬盘有偏差）
DWORD RVAToFOA(PE_CONTEXT pe,DWORD Address) {
	PIMAGE_FILE_HEADER pFileHeader{ &pe.pNT->FileHeader };
	PIMAGE_OPTIONAL_HEADER32 pPEHeader{ &pe.pNT->OptionalHeader };
	PIMAGE_SECTION_HEADER pSectionTable{ (PIMAGE_SECTION_HEADER)((BYTE*)pPEHeader + pFileHeader->SizeOfOptionalHeader) };
	
	//如果地址不在节内返回
	if (Address <= pPEHeader->SizeOfHeaders) return 0;

	//定位所在节
	int PointOfSection{-1};
	DWORD SectionSize{};
	for (int i{}; i < pFileHeader->NumberOfSections; i++) {
		//判断节的大小
		//VirtualSize可能为0
		if (!pSectionTable[i].Misc.VirtualSize) {
			SectionSize = pSectionTable[i].SizeOfRawData;
		}
		else {
			SectionSize = pSectionTable[i].Misc.VirtualSize < pSectionTable[i].SizeOfRawData ? pSectionTable[i].Misc.VirtualSize : pSectionTable[i].SizeOfRawData;
		}
		if (Address >= pSectionTable[i].VirtualAddress &&
			Address < pSectionTable[i].VirtualAddress + SectionSize) {
			PointOfSection = i;
			break;
		}
	}
	if (PointOfSection == -1) {
		return 0;
	}
	//得到相对位置
	DWORD OffsetInSection = Address - pSectionTable[PointOfSection].VirtualAddress;
	//返回FOA
	return pSectionTable[PointOfSection].PointerToRawData + OffsetInSection;
}


//关闭ALSR地址随机化,只修改内存,还需写入
BOOL CloseAddressRandomisation(PE_CONTEXT pe) {
	if ((pe.pNT->Signature!=IMAGE_NT_SIGNATURE)||(pe.pDos->e_magic!=IMAGE_DOS_SIGNATURE)) {
		std::cout << "[-]确认当前函数是否为PE文件" << std::endl;
	}
	pe.pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	if (pe.pNT->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		return FALSE;
	}
	return TRUE;
}