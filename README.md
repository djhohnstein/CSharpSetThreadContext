# Disclaimer

The code provided is "as is" and will not be supported.

# CSharp SetThreadContext Shellcode Runner Example

This project is a C# port of the work @xpn did in his blog post here:

https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/

We only tackle the SetThreadContext portion here, though the building blocks to perform all three tasks are here.

This project first determines a suitable executable to spawn, decrypts shellcode using a predefined key, then uses CreateRemoteThread and SetThreadContext to ensure that the remote thread is backed by a file on disk, effectively evading `Get-InjectedThread`.

## Usage

The solution file is in `Cryptor\ThreadContextRunner.sln`. Open this and view the two projects. If you wish to change the encryption key, you'll need to change it both in `Cryptor` and `Runner` projects.

Right click `Cryptor` in the solution pane and click "Build". This will build the executable, `Cryptor.exe`, that will encrypt your shellcode. Run this by: `Cryptor.exe C:\Path\To\Shellcode.bin`. This generates a new file, `encrypted.bin`.

Next, right click the `Runner` project in the Solution Explorer on the right hand side and click "Properties". Go to Resources then add a new File resource. Navigate to the folder where `encrypted.bin` was generated and add it as a resource. Then, click this new resource in the Solution Explorer and ensure that the Build Action is set to "Embedded Resource".

Now you can rebuild the entire solution. `Runner.exe` will be generated and should be suitable to run your shellcode when double clicked.

## Special Thanks

@xpn and @its_a_feature for their excellent blog and teaching me C/C++ respectively.
