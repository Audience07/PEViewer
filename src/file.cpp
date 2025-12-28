#include "../include/file.h"

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