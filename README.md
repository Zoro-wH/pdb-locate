# pdb-locate
一个自动化定位特征码源码的工具，根据特征码的在二进制中的Fileoffset通过计算定位到源代码中的具体某一行。

目前只能适用于Debug版本（由于Release版本编译出来的pdb差异）
代码核心思路：

1. **获取基地址**

   - 调用 **Tool Help Library API** (CreateToolhelp32Snapshot 等)，在当前所有正在运行的进程中查找目标进程，并获取它这次被加载到的**随机内存基地址** **(Base Address)**。

2. **计算最终地址**

   - 解析文件的 **PE (Portable Executable) 头**，提取PointerToRawData和VirtualAddress。通过公式 最终地址 = 随机基地址 + (文件偏移 - 静态偏移)，计算出这个特征码最终地址。

3. **查询PDB**

   - 调用函数 **SymGetLineFromAddrW64** (DbgHelp 库中的W64 版本支持长路径,解决路径被截断问题)。

     > https://learn.microsoft.com/zh-cn/windows/win32/api/dbghelp/nf-dbghelp-symgetlinefromaddr64
     >
     > 查找指定地址的源行。

   - 查询 **PDB 文件**找到 特征码在某个.cpp 文件的第 XX 行。”

   - 最后，程序打开那个 .cpp 文件，读出第 XX 行的内容，并将所有结果一起显示。

   

用法 1: find.exe <目标EXE路径>  [offset1]  [offset2] ...

用法 2: find.exe <目标EXE路径> -f <包含offset列表的文件>
