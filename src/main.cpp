#include "../include/PEViewer.h"

int main(int argc,char* argv[]) {
	//变量
	//const char* path = argv[1];
	const char* path = argv[1];
	//判断路径
	if (!check_path_win(path)) return 0;
	//载入内存
	PE_CONTEXT pe = LoadFileToMemory(path);
	//读取数据
	ReadField(pe);
}