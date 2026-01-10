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
DWORD RVAToFOA(const PE_CONTEXT &pe,DWORD Address) {
	PIMAGE_FILE_HEADER pFileHeader{ &pe.pNT->FileHeader };
	PIMAGE_OPTIONAL_HEADER32 pPEHeader{ &pe.pNT->OptionalHeader };
	PIMAGE_SECTION_HEADER pSectionTable{ (PIMAGE_SECTION_HEADER)((BYTE*)pPEHeader + pFileHeader->SizeOfOptionalHeader) };
	PIMAGE_SECTION_HEADER* ppSectionTable{ (PIMAGE_SECTION_HEADER*)_alloca(sizeof(PIMAGE_SECTION_HEADER*) * pFileHeader->NumberOfSections) };
	//如果地址不在节内返回
	if (Address <= pPEHeader->SizeOfHeaders) return Address;

	//定位所在节
	int PointOfSection{-1};
	DWORD SectionSize{};
	for (int i{}; i < pFileHeader->NumberOfSections; i++) {
		//建立映射关系
		ppSectionTable[i] = &pSectionTable[i];
		//判断节的大小
		//VirtualSize可能为0
		if (!(ppSectionTable[i]->Misc.VirtualSize)) {
			SectionSize = ppSectionTable[i]->SizeOfRawData;
		}
		else {
			SectionSize = SectionSize = ppSectionTable[i]->Misc.VirtualSize;
		}
		
		if (Address >= ppSectionTable[i]->VirtualAddress &&
			Address < ppSectionTable[i]->VirtualAddress + SectionSize) {
			PointOfSection = i;
			break;
		}
		
	}
	if (PointOfSection==-1) {
		return 0;
	}
	//得到相对位置
	DWORD OffsetInSection = Address - ppSectionTable[PointOfSection]->VirtualAddress;
	//返回FOA
	return ppSectionTable[PointOfSection]->PointerToRawData + OffsetInSection;
}


//关闭ALSR地址随机化,只修改内存,还需写入
BOOL CloseAddressRandomisation(const PE_CONTEXT& pe) {
	if (!pe.isVaild) {
		std::cout << "[-]确认当前函数是否为PE文件" << std::endl;
	}
	pe.pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	if (pe.pNT->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		return FALSE;
	}
	return TRUE;
}

//遍历导入表DLL
VOID TraverseImportTable(const PE_CONTEXT& pe) {
	//到如表大小
	//DWORD pImportSize{ pe.pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size };
	PIMAGE_IMPORT_DESCRIPTOR pImportTable{(PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pe.pFileBuffer + RVAToFOA(pe, (DWORD)pe.pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress))};
	int i{};
	std::cout << "----------------------------------ImportTable---------------------------------------" << std::endl;
	std::cout << "Name:" << std::endl;
	
	while (1) {
		if (!(RVAToFOA(pe, pImportTable[i].Name))) break;
		//DLL名称
		std::cout << "[+]" << (BYTE*)pe.pFileBuffer + RVAToFOA(pe , pImportTable[i].Name) << std::endl;
		i++;
	}
}