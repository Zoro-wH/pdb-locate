#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <tchar.h>
#include <string>
#include <winnt.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "dbghelp.lib")

// ====================================================================================
// 辅助函数部分
// ====================================================================================

std::wstring Utf8ToWstring(const char* utf8_str) { if (!utf8_str || *utf8_str == '\0') return L""; int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0); if (len == 0) return L""; std::wstring wstr(len, 0); MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, &wstr[0], len); wstr.resize(wcslen(wstr.c_str())); return wstr; }
void PrintW(const std::wstring& wstr) { HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); DWORD charsWritten; WriteConsoleW(hConsole, wstr.c_str(), (DWORD)wstr.length(), &charsWritten, NULL); }
std::wstring ToHexWString(DWORD64 value) { std::wstringstream wss; wss << L"0x" << std::hex << value; return wss.str(); }

bool ParseOffsetString(const std::wstring& s, DWORD64& offset) {
    try {
        std::wstring cleanStr = s;
        if (s.rfind(L"0x", 0) == 0 || s.rfind(L"0X", 0) == 0) {
            cleanStr = s.substr(2);
        }
        offset = std::stoull(cleanStr, nullptr, 16);
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool ReadOffsetsFromFile(const std::wstring& filePath, std::vector<DWORD64>& offsets) {
    std::wifstream file(filePath);
    if (!file.is_open()) {
        PrintW(L"错误：无法打开offset文件: " + filePath + L"\n");
        return false;
    }
    std::wstring line;
    while (std::getline(file, line)) {
        DWORD64 offset;
        if (ParseOffsetString(line, offset)) {
            offsets.push_back(offset);
        }
    }
    return true;
}

void PrintSourceLine(const std::wstring& wFilePath, DWORD lineNumber) {
    std::ifstream file(wFilePath);
    if (!file.is_open()) {
        PrintW(L"    -> 错误：无法打开源文件进行读取。请确认路径:\n       " + wFilePath + L"\n       是否存在且可访问。\n");
        return;
    }
    std::string line;
    for (DWORD i = 1; i <= lineNumber; ++i) {
        if (!std::getline(file, line)) {
            PrintW(L"    -> 错误：文件行数不足 " + std::to_wstring(lineNumber) + L" 行或读取失败。\n");
            return;
        }
    }
    PrintW(L"Source Line: " + Utf8ToWstring(line.c_str()) + L"\n");
}

// ====================================================================================
// **核心部分：PE文件静态解析**
// ====================================================================================

DWORD64 GetImageBaseFromFile(LPVOID fileBaseAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBaseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("无效的PE文件：缺少DOS签名。");
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBaseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("无效的PE文件：缺少NT签名。");
    }
    return ntHeaders->OptionalHeader.ImageBase;
}

DWORD64 FileOffsetToRVA(LPVOID fileBaseAddress, DWORD64 fileOffset) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBaseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBaseAddress + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        DWORD rawDataStart = sectionHeader->PointerToRawData;
        DWORD rawDataSize = sectionHeader->SizeOfRawData;
        if (fileOffset >= rawDataStart && fileOffset < rawDataStart + rawDataSize) {
            return (fileOffset - rawDataStart) + sectionHeader->VirtualAddress;
        }
    }

    // **使用 stringstream 构建复杂的错误信息**
    std::stringstream ss;
    ss << "文件偏移地址 0x" << std::hex << fileOffset << " 未在任何PE节区中找到。";
    throw std::runtime_error(ss.str());
}


// ====================================================================================
// **主函数**
// ====================================================================================

int _tmain(int argc, _TCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 3) {
        PrintW(L"用法 1: find.exe <目标EXE/DLL路径> <offset1> [offset2] ...\n");
        PrintW(L"用法 2: find.exe <目标EXE/DLL路径> -f <包含offset列表的文件>\n\n");
        PrintW(L"示例 1: find.exe \"C:\\path\\to\\MyTest.exe\" 0x15ef0 0x1ddeb\n");
        PrintW(L"示例 2: find.exe \"C:\\path\\to\\MyModule.dll\" -f offsets.txt\n");
        system("pause");
        return 1;
    }

    const TCHAR* modulePath = argv[1];
    std::vector<DWORD64> fileOffsets;

    if (argc == 4 && _wcsicmp(argv[2], L"-f") == 0) {
        if (!ReadOffsetsFromFile(argv[3], fileOffsets)) { system("pause"); return 1; }
        PrintW(L"已从文件 \"" + std::wstring(argv[3]) + L"\" 读取 " + std::to_wstring(fileOffsets.size()) + L" 个偏移。\n\n");
    }
    else {
        for (int i = 2; i < argc; ++i) {
            DWORD64 offset;
            if (ParseOffsetString(argv[i], offset)) { fileOffsets.push_back(offset); }
            else { PrintW(L"警告：无法解析偏移 '" + std::wstring(argv[i]) + L"', 已跳过。\n"); }
        }
    }

    if (fileOffsets.empty()) { PrintW(L"错误：没有提供任何有效的偏移值。\n"); system("pause"); return 1; }

    HANDLE hFile = CreateFile(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { PrintW(L"错误：无法打开文件 " + std::wstring(modulePath) + L"\n"); system("pause"); return 1; }
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) { CloseHandle(hFile); PrintW(L"错误：无法创建文件映射。\n"); system("pause"); return 1; }
    LPVOID fileBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBaseAddress == NULL) { CloseHandle(hMapping); CloseHandle(hFile); PrintW(L"错误：无法映射文件视图。\n"); system("pause"); return 1; }

    DWORD64 imageBase = 0;
    try {
        imageBase = GetImageBaseFromFile(fileBaseAddress);
        PrintW(L"成功！已从文件头静态获取ImageBase: " + ToHexWString(imageBase) + L"\n\n");

        HANDLE hProcess = GetCurrentProcess();
        if (!SymInitialize(hProcess, NULL, TRUE)) {
            std::stringstream ss;
            ss << "SymInitialize failed, error: " << GetLastError();
            throw std::runtime_error(ss.str());
        }

        DWORD64 moduleBase = SymLoadModuleExW(hProcess, NULL, modulePath, NULL, imageBase, 0, NULL, 0);
        if (moduleBase == 0) {
            std::stringstream ss;
            ss << "SymLoadModuleExW failed, error: " << GetLastError() << "\n请确认PDB文件与目标文件在同一目录下。";
            throw std::runtime_error(ss.str());
        }

        for (const auto& fileOffset : fileOffsets) {
            PrintW(L"======================================================\n");
            PrintW(L"正在处理 File Offset: " + ToHexWString(fileOffset) + L"\n");
            PrintW(L"------------------------------------------------------\n");

            try {
                DWORD64 rva = FileOffsetToRVA(fileBaseAddress, fileOffset);
                DWORD64 finalAddress = imageBase + rva;

                IMAGEHLP_LINEW64 lineInfo;
                DWORD displacement;
                lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);

                if (SymGetLineFromAddrW64(hProcess, finalAddress, &displacement, &lineInfo)) {
                    std::wstring wFilePath = lineInfo.FileName;
                    PrintW(L"Address: " + ToHexWString(finalAddress) + L"\n");
                    PrintW(L"Source File: " + wFilePath + L"\n");
                    PrintW(L"Line Number: " + std::to_wstring(lineInfo.LineNumber) + L"\n");
                    PrintSourceLine(wFilePath, lineInfo.LineNumber);
                }
                else {
                    PrintW(L"SymGetLineFromAddrW64 failed for address " + ToHexWString(finalAddress) + L", error: " + std::to_wstring(GetLastError()) + L"\n");
                }
            }
            catch (const std::runtime_error& e) {
                PrintW(L"处理偏移 " + ToHexWString(fileOffset) + L" 时发生错误: " + Utf8ToWstring(e.what()) + L"\n");
            }
            PrintW(L"\n");
        }
        SymCleanup(hProcess);
    }
    catch (const std::runtime_error& e) {
        PrintW(L"程序发生严重错误: " + Utf8ToWstring(e.what()) + L"\n");
    }

    UnmapViewOfFile(fileBaseAddress);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    system("pause");
    return 0;
}