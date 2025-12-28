# PEViewer

一个基于 **Windows / C++** 的命令行 PE 文件字段读取工具  
用于学习和分析 **PE（Portable Executable）文件结构**

---

## ✨ 功能简介

PEViewer 可以：

- 将 PE 文件完整加载到内存
- 校验 DOS Header 与 NT Header
- 解析并输出：
  - DOS Header
  - FILE Header
  - OPTIONAL Header
  - Section Table（节表）
- 以命令行形式直观展示关键字段信息

适合用途：

- PE 文件结构学习
- 逆向工程入门
- 恶意代码分析前的静态查看
- Loader / PE 解析器编写练习

---

## 📁 项目结构

```text
PEViewer/
├── include/
│   └── PEViewer.h
├── src/
│   └── main.cpp
│   └── PEViewer.cpp
└── README.md
```
---

## 🛠️ 编译环境

- 操作系统：Windows

- 编译器：MSVC（Visual Studio）

- 语言标准：C++17（或以上）

    - 依赖库：

    - Windows API（Windows.h）

    - C / C++ 标准库

---

## 🚀 使用方式
```bash
PEViewer.exe <PE文件路径>
```
示例：
```bash
PEViewer.exe C:\Windows\System32\notepad.exe
```

---

## 🧠 核心实现说明
### PE 文件加载到内存
```cpp
PE_CONTEXT LoadFileToMemory(IN LPCSTR str);
```


实现流程：

1.使用 fopen 以二进制方式打开文件

2.使用 fseek + ftell 获取文件大小

3.使用 malloc 分配文件缓冲区

4.使用 fread 将文件完整读入内存

5.初始化 PE 关键结构指针：
- IMAGE_DOS_HEADER

- IMAGE_NT_HEADERS32

6.校验 PE 文件合法性

**关键校验逻辑：**
```cpp
if (pe.pDos->e_magic != IMAGE_DOS_SIGNATURE) return pe;
if (pe.pNT->Signature != IMAGE_NT_SIGNATURE) return pe;
```

---

### 📌 输出示例
```powershell
------------------------------------DosHeader-----------------------------------------
[+]e_magic:0x5a4d

------------------------------------FileHeader----------------------------------------
[+]Machine:0x14c
[+]NumberOfSections:5
[+]SizeOfOptionalHeader:0xe0
[+]Megic:0x10b
[+]AddressOfEntryPoint:0x13a0
[+]ImageBase:0x400000

------------------------------------SectionTable--------------------------------------
.text:
[+]VirtualSize:0x1234
[+]VirtualAddress:0x1000
[+]SizeOfRawData:0x1400
[+]PointerToRawData:0x400
```

---

### ⚠️ 注意事项

- 当前版本仅支持 PE32（32 位）
    - PE32+（64 位）支持

    - RVA ↔ FOA 转换

    - Data Directory 解析
- 使用 malloc 分配的内存需手动 free

---


### 📜 License

本项目仅用于 学习、研究和教学目的请勿用于任何非法用途
