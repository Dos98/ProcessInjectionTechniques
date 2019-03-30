# ProcessInjectionTechniques
Learning Various Process Injection Techniques


Method                 | 32 bits | 64 bits |  DLL to use                     |
-----------------------|---------|---------|---------------------------------|
 CreateRemoteThread()  |    +    |    +    | dllmain_32.dll / dllmain_64.dll |
 NtCreateThreadEx()    |    +    |    +    | dllmain_32.dll / dllmain_64.dll |
 QueueUserAPC()        |    +    |    +    | dllmain_32.dll / dllmain_64.dll |
 SetWindowsHookEx()    |    +    |    +    |  dllpoc_32.dll / dllpoc_64.dll  |
 RtlCreateUserThread() |    +    |    +    | dllmain_32.dll / dllmain_64.dll |
 SetThreadContext()    |    +    |    +    | dllmain_32.dll / dllmain_64.dll |
 Reflective DLL        |    +    |    +    |    rdll_32.dll / rdll_64.dll    |