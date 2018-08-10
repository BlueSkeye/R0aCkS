using System;
using System.Runtime.InteropServices;

using Microsoft.Win32;

namespace R0aCkS
{
    internal static class SymbolHandling
    {
        internal static UIntPtr GetDriverBaseAddr(string BaseName)
        {
            UIntPtr[] BaseAddresses = new UIntPtr[1024];
            uint cbNeeded;

            // Enumerate all the device drivers
            if (!Natives.EnumDeviceDrivers(BaseAddresses, (uint)(IntPtr.Size * BaseAddresses.Length), out cbNeeded)) {
                Console.WriteLine("[-] Failed to enumerate driver base addresses: 0x{0:8X}", Marshal.GetLastWin32Error());
                return UIntPtr.Zero;
            }
            IntPtr buffer = IntPtr.Zero;
            const int bufferLength = 260;
            try {
                buffer = Marshal.AllocHGlobal(bufferLength);
                // Go through each one
                for (int index = 0; index < (cbNeeded / IntPtr.Size); index++) {
                    // Get its name
                    if (0 == Natives.GetDeviceDriverBaseNameA(BaseAddresses[index], buffer, bufferLength)) {
                        Console.WriteLine("[-] Failed to get driver name: 0x{0:8X}", Marshal.GetLastWin32Error());
                        return UIntPtr.Zero;
                    }
                    // Compare it
                    string candidate = Marshal.PtrToStringAnsi(buffer);
                    if (0 == string.Compare(candidate, BaseName, true)) {
                        return BaseAddresses[index];
                    }
                }
            }
            finally {
                if (IntPtr.Zero != buffer) { Marshal.FreeHGlobal(buffer); }
            }
            return UIntPtr.Zero;
        }

        // Was SymSetup
        internal static void Initialize()
        {
            RegistryKey rootKey = null;
            RegistryKey localMachineKey = null;

            // Open the Kits key
            try {
                try {
                    localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                    rootKey = localMachineKey.OpenSubKey(@"Software\Microsoft\Windows Kits\Installed Roots");
                }
                catch {
                    Console.WriteLine("[-] No Windows SDK or WDK installed: 0x{0:X8}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Check where a kit was installed
                string rootPath = null;
                try { rootPath = (string)rootKey.GetValue("KitsRoot10", null); }
                catch { }
                finally {
                    if (null == rootPath) {
                        Console.WriteLine("[-] Win 10 SDK/WDK not found, falling back to 8.1: 0x{0:X8}", Marshal.GetLastWin32Error());
                        try { rootPath = (string)rootKey.GetValue("KitsRoot81", null); }
                        catch { }
                        finally {
                            if (null == rootPath) {
                                Console.WriteLine("[-] Win 8.1 SDK / WDK not found, falling back to 8: 0x{ 0:X8}", Marshal.GetLastWin32Error());
                                try { rootPath = (string)rootKey.GetValue("KitsRoot8", null); }
                                catch { }
                                finally {
                                    if (null == rootPath) {
                                        Console.WriteLine("[-] Win 8 SDK / WDK not found 0x{ 0:X8}", Marshal.GetLastWin32Error());
                                    }
                                }
                            }
                        }
                    }
                }
                if (null == rootPath) {
                    throw new ApplicationException();
                }
                // Now try to load the correct debug help library
                rootPath += "debuggers\\x64\\dbghelp.dll";
                IntPtr hMod = IntPtr.Zero;
                try { hMod = Natives.LoadLibrary(rootPath); }
                catch { }
                if (IntPtr.Zero == hMod) {
                    Console.WriteLine("[-] Failed to load Debugging Tools Dbghelp.dll: 0x{0:X8}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Get the APIs that we need
                if (!InitializeBridgeDelegate(hMod, "SymSetOptions", out pSymSetOptions)) {
                    throw new ApplicationException();
                }
                if (!InitializeBridgeDelegate(hMod, "SymInitializeW", out pSymInitializeW)) {
                    throw new ApplicationException();
                }
                if (!InitializeBridgeDelegate(hMod, "SymLoadModuleEx", out pSymLoadModuleEx)) {
                    throw new ApplicationException();
                }
                if (!InitializeBridgeDelegate(hMod, "SymGetSymFromName64", out pSymGetSymFromName64)) {
                    throw new ApplicationException();
                }
                if (!InitializeBridgeDelegate(hMod, "SymUnloadModule64", out pSymUnloadModule64)) {
                    throw new ApplicationException();
                }

                // Initialize the engine
                pSymSetOptions(0x00000004 /*SYMOPT_DEFERRED_LOADS*/);
                if (!pSymInitializeW(Natives.GetCurrentProcess(), null, true)) {
                    Console.WriteLine("[-] Failed to initialize symbol engine: 0x{0:X8}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Initialize our gadgets
                g_XmFunction = Lookup("hal.dll", "XmMovOp");
                g_TrampolineFunction = Lookup("ntoskrnl.exe", "PopFanIrpComplete");
                // HSTI = Hardware Security Test Interface
                // See https://docs.microsoft.com/fr-fr/windows-hardware/test/hlk/testref/hardware-security-testability-specification
                g_HstiBufferSize = Lookup("ntoskrnl.exe", "SepHSTIResultsSize");
                g_HstiBufferPointer = Lookup("ntoskrnl.exe", "SepHSTIResultsBuffer");
            }
            finally {
                if (null != rootKey) { rootKey.Dispose(); }
                if (null != localMachineKey) { localMachineKey.Dispose(); }
            }
            return;
        }

        private static bool InitializeBridgeDelegate<T>(IntPtr hMod, string functionName, out T pointer)
        {
            IntPtr dynamicFunction = Natives.GetProcAddress(hMod, functionName);
            if (IntPtr.Zero == dynamicFunction) {
                Console.WriteLine("[-] Failed to find {0}. Err 0x{1:X4}",
                    functionName, Marshal.GetLastWin32Error());
                pointer = default(T);
                return false;
            }
            pointer = (T)(object)Marshal.GetDelegateForFunctionPointer(dynamicFunction, typeof(T));
            return true;
        }

        internal static unsafe UIntPtr Lookup(string ModuleName, string SymbolName)
        {
            UIntPtr imageBase = UIntPtr.Zero;
            UIntPtr kernelBase = UIntPtr.Zero;
            ulong offset;
            UIntPtr /* PIMAGEHLP_SYMBOL64 */ symbol = UIntPtr.Zero;
            UIntPtr realKernelBase;

            try {
                // Get the base address of the kernel image in kernel-mode
                realKernelBase = GetDriverBaseAddr(ModuleName);
                if (UIntPtr.Zero == realKernelBase) {
                    Console.WriteLine("[-] Couldn't find base address for {0}", ModuleName);
                    throw new ApplicationException();
                }

                // Load the kernel image in user-mode
                kernelBase = Natives.LoadLibraryExA(ModuleName, IntPtr.Zero, 0x00000001 /* DONT_RESOLVE_DLL_REFERENCES*/);
                if (UIntPtr.Zero == kernelBase) {
                    Console.WriteLine("[-] Couldn't map {0}!", ModuleName);
                    throw new ApplicationException();
                }

                // Allocate space for a symbol buffer
                symbol = (UIntPtr)Natives.HeapAlloc(Natives.GetProcessHeap(), 0x00000008 /* HEAP_ZERO_MEMORY */,
                    (uint)(Marshal.SizeOf<IMAGEHLP_SYMBOL64>() + 2));
                if (UIntPtr.Zero == symbol) {
                    Console.WriteLine("[-] Not enough memory to allocate IMAGEHLP_SYMBOL64");
                    throw new ApplicationException();
                }

                // Attach symbols to our module
                imageBase = pSymLoadModuleEx(Natives.GetCurrentProcess(), IntPtr.Zero, ModuleName, ModuleName,
                    kernelBase, 0, UIntPtr.Zero, 0);
                if (imageBase != kernelBase) {
                    Console.WriteLine("[-] Couldn't load symbols for {0}", ModuleName);
                    throw new ApplicationException();
                }

                // Build the symbol name
                string symName = ModuleName + "!" + SymbolName;

                // Look it up
                Marshal.WriteInt32(symbol, 0, Marshal.SizeOf<IMAGEHLP_SYMBOL64>());
                // symbol->SizeOfStruct = sizeof(*symbol);
                Marshal.WriteInt32(symbol, (int)Marshal.OffsetOf<IMAGEHLP_SYMBOL64>("MaxNameLength"), 1);
                // symbol->MaxNameLength = 1;
                if (!pSymGetSymFromName64(Natives.GetCurrentProcess(), symName, symbol)) {
                    Console.WriteLine("[-] Couldn't find {0} symbol : Err 0x{1:X8}",
                        symName, Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Compute the offset based on the mapped address
                offset = ((ulong)Marshal.ReadIntPtr(symbol, 4) /* symbol->Address */ - (ulong)kernelBase);
            }
            catch {
                Console.WriteLine("[-] Failed to find {0}!{1}", ModuleName, SymbolName);
                throw;
            }
            finally {
                if (UIntPtr.Zero != kernelBase) {
                    Natives.FreeLibrary(kernelBase);
                }
                if (UIntPtr.Zero != imageBase) {
                    pSymUnloadModule64(Natives.GetCurrentProcess(), imageBase);
                }
                if (UIntPtr.Zero != symbol) {
                    Natives.HeapFree(Natives.GetProcessHeap(), 0, symbol);
                }
            }
            // Compute the final location based on the real kernel base
            return (UIntPtr)((ulong)realKernelBase + offset);
        }

        private static SymGetSymFromName64Delegate pSymGetSymFromName64;
        private static SymInitializeWDelegate pSymInitializeW;
        private static SymLoadModuleExDelegate pSymLoadModuleEx;
        private static SymSetOptionsDelegate pSymSetOptions;
        private static SymUnloadModule64Delegate pSymUnloadModule64;

        internal static UIntPtr g_HstiBufferPointer;
        internal static UIntPtr g_HstiBufferSize;
        internal static UIntPtr g_TrampolineFunction;
        internal static UIntPtr g_XmFunction;

        private delegate bool SymGetSymFromName64Delegate(
            [In] IntPtr hProcess,
            [In, MarshalAs(UnmanagedType.LPStr)] string Name,
            [In] UIntPtr /* PIMAGEHLP_SYMBOL64 */ Symbol);
        private delegate bool SymInitializeWDelegate(
            [In] IntPtr hProcess,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UserSearchPath,
            [In] bool fInvadeProcess);
        private delegate UIntPtr SymLoadModuleExDelegate(
            [In] IntPtr hProcess,
            [In] IntPtr hFile,
            [In, MarshalAs(UnmanagedType.LPStr)] string ImageName,
            [In, MarshalAs(UnmanagedType.LPStr)] string ModuleName,
            [In] UIntPtr BaseOfDll,
            [In] uint DllSize,
            [In] UIntPtr /* MODLOAD_DATA */ Data,
            [In] uint Flags);
        private delegate bool SymUnloadModule64Delegate(
            [In] IntPtr hProcess,
            [In] UIntPtr BaseOfDll);
        private delegate uint SymSetOptionsDelegate(
            [In] uint SymOptions);

        private struct IMAGEHLP_SYMBOL64
        {
            internal uint SizeOfStruct;
            internal IntPtr Address;
            internal uint Size;
            internal uint Flags;
            internal uint MaxNameLength;
            internal char Name;
        }
    }
}
