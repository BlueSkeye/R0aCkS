using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace R0aCkS
{
    internal class EtwTracer
    {
        internal unsafe EtwTracer()
        {
            _context = (Context*)Marshal.AllocHGlobal(Marshal.SizeOf<Context>());
        }

        private unsafe void EtpEtwEventCallback(Natives.EVENT_RECORD* EventRecord)
        {
            Context* context;

            // Look for an "end of work item execution event"
            if (EventRecord->EventHeader.EventDescriptor.Opcode ==
                (PERFINFO_LOG_TYPE_WORKER_THREAD_ITEM_END & 0xFF))
            {
                // Grab our context and check if the work routine matches ours
                context = (Context*)EventRecord->UserContext;
                if ((UIntPtr)EventRecord->UserData == context->WorkItemRoutine)
                {
                    // Stop the trace -- this callback will run a few more times
                    Console.WriteLine("[+] Kernel finished executing work item at               0x{0:X16}",
                        context->WorkItemRoutine);
                    Natives.ControlTrace(context->SessionHandle, UIntPtr.Zero, context->Properties,
                        1 /* EVENT_TRACE_CONTROL_STOP*/);
                }
            }
        }

        internal unsafe void ParseSession()
        {
            // Process the trace until the right work item is found
            uint errorCode;
            if (0 != (errorCode = Natives.ProcessTrace((IntPtr)(&_context->ParserHandle), 1, null, null))) {
                Console.WriteLine("[-] Failed to process trace: 0x{0:X}", errorCode);
                Natives.ControlTrace(_context->SessionHandle, UIntPtr.Zero, _context->Properties,
                    1 /* EVENT_TRACE_CONTROL_STOP*/);
            }
            // All done -- cleanup
            Natives.CloseTrace(_context->ParserHandle);
            Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)(&_context->Properties));
            if (0 != errorCode) {
                throw new ApplicationException();
            }
            return;
        }

        internal unsafe void StartSession(UIntPtr WorkItemRoutine)
        {
            uint errorCode;
            int traceFlagsCount = 8;
            uint* traceFlags = stackalloc uint[traceFlagsCount];
            Natives.EVENT_TRACE_LOGFILE logFile = new Natives.EVENT_TRACE_LOGFILE();

            for(int index = 0; index < traceFlagsCount; index++) {
                traceFlags[index] = 0;
            }
            // Allocate memory for our session descriptor
            uint bufferSize = (uint)(Marshal.SizeOf<Natives.EVENT_TRACE_PROPERTIES>() + Marshal.SizeOf(g_EtwTraceName));
            _context->Properties = (Natives.EVENT_TRACE_PROPERTIES*)Marshal.AllocHGlobal((int)bufferSize);
            // Natives.HeapAlloc(Natives.GetProcessHeap(), 0x00000008 /* HEAP_ZERO_MEMORY */, bufferSize);
            if (null == _context->Properties) {
                Console.WriteLine("[-] Failed to allocate memory for the ETW trace");
                throw new ApplicationException();
            }

            // Create a real-time session using the system logger, tracing nothing
            _context->Properties->Initialize();
            _context->Properties->Wnode.BufferSize = bufferSize;
            _context->Properties->Wnode.Guid = g_EtwTraceGuid;
            _context->Properties->Wnode.ClientContext = 1;
            _context->Properties->Wnode.Flags = 0x00020000 /*WNODE_FLAG_TRACED_GUID*/;
            _context->Properties->MinimumBuffers = 1;
            _context->Properties->LogFileMode = 0x02000100 /* EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE */;
            _context->Properties->FlushTimer = 1;
            _context->Properties->LoggerNameOffset = (uint)Marshal.SizeOf<Natives.EVENT_TRACE_PROPERTIES>();
            if (0 != (errorCode = Natives.StartTrace(out _context->SessionHandle, g_EtwTraceName, _context->Properties))) {
                Console.WriteLine("[-] Failed to create the event trace session: %lX\n", errorCode);
                Marshal.FreeHGlobal((IntPtr)_context->Properties);
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)_context->Properties);
                throw new ApplicationException();
            }
            // Open a consumer handle to it
            logFile.LoggerName = Marshal.StringToHGlobalUni(g_EtwTraceName);
            logFile.ProcessTraceMode = 0x10000100 /* PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD*/;
            logFile.EventRecordCallback = Marshal.GetFunctionPointerForDelegate<Natives.EventRecordCallbackDelegate>(EtpEtwEventCallback);
            logFile.Context = (UIntPtr)_context;
            _context->ParserHandle = Natives.OpenTrace(&logFile);
            if (_context->ParserHandle == Natives.InvalidHandle) {
                Console.WriteLine("[-] Failed open a consumer handle for the trace session: 0x{0:X}", Marshal.GetLastWin32Error());
                Natives.ControlTrace(_context->SessionHandle, UIntPtr.Zero, _context->Properties,
                    1 /* EVENT_TRACE_CONTROL_STOP*/);
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)_context->Properties);
                Marshal.FreeHGlobal((IntPtr)_context);
                throw new ApplicationException();
            }
            // Trace worker thread events
            traceFlags[2] = PERF_WORKER_THREAD;
            if (0 != Natives.TraceSetInformation(_context->SessionHandle, 4 /* TraceSystemTraceEnableFlagsInfo*/,
                (UIntPtr)traceFlags, (uint)traceFlagsCount * sizeof(uint)))
            {
                Console.WriteLine("[-] Failed to set flags for event trace session: 0x{0:X}", errorCode);
                Natives.ControlTrace(_context->SessionHandle, UIntPtr.Zero, _context->Properties,
                    1 /* EVENT_TRACE_CONTROL_STOP*/);
                Natives.CloseTrace(_context->ParserHandle);
                // Natives.HeapFree(Natives.GetProcessHeap(), 0, (UIntPtr)_context->Properties);
                Marshal.FreeHGlobal((IntPtr)_context->Properties);
                throw new ApplicationException();
            }
            // Remember which work routine we'll be looking for
            _context->WorkItemRoutine = WorkItemRoutine;
            return;
        }

        private const uint EVENT_TRACE_GROUP_THREAD = 0x0500;
        private const uint PERFINFO_LOG_TYPE_WORKER_THREAD_ITEM_END = (EVENT_TRACE_GROUP_THREAD | 0x41);
        private const uint PERF_WORKER_THREAD = 0x48000000;
        private static readonly Guid g_EtwTraceGuid = new Guid(0x53636210, 0xbe24, 0x1264, 0xc6, 0xa5, 0xf0, 0x9c, 0x59, 0x88, 0x1e, 0xbd);
        private const string g_EtwTraceName = "r0ak-etw";
        private unsafe Context* _context;

        private struct Context
        {
            internal IntPtr SessionHandle;
            internal IntPtr ParserHandle;
            internal unsafe Natives.EVENT_TRACE_PROPERTIES* Properties;
            internal UIntPtr WorkItemRoutine;
        }
    }
}
