using System;
using System.Runtime.InteropServices;
using System.Text;

namespace R0aCkS
{
    internal static class Natives
    {
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int AddFontResourceExW(
            [In] string name,
            [In] uint fl,
            [In] UIntPtr res);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool CloseHandle(
            [In] IntPtr hObject);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern uint CloseTrace(
            [In] IntPtr /* TRACEHANDLE */ TraceHandle);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern unsafe uint ControlTrace(
            [In] IntPtr SessionHandle,
            [In] UIntPtr /* LPCTSTR */ SessionName,
            [In] EVENT_TRACE_PROPERTIES* Properties,
            [In] uint ControlCode);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool CreatePipe(
            [Out] out IntPtr hReadPipe,
            [Out] out IntPtr hWritePipe,
            [In] UIntPtr /* LPSECURITY_ATTRIBUTES */ lpPipeAttributes,
            [In] uint nSize);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern IntPtr CreateToolhelp32Snapshot(
            [In] uint dwFlags,
            [In] uint th32ProcessID);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern bool DuplicateToken(
            [In] IntPtr ExistingTokenHandle,
            [In] uint /*SECURITY_IMPERSONATION_LEVEL*/ ImpersonationLevel,
            [Out] out IntPtr DuplicateTokenHandle);
        /// <summary></summary>
        /// <param name="lpImageBase"></param>
        /// <param name="cb"></param>
        /// <param name="lpcbNeeded"></param>
        /// <returns></returns>
        /// <remarks>See documentation on MSDN for reason of entry point renaming. Probably working since
        /// Windows 8 and later versions.</remarks>
        [DllImport("KERNEL32.DLL", EntryPoint = "K32EnumDeviceDrivers", SetLastError = true)]
        internal static extern bool EnumDeviceDrivers(
            [In] UIntPtr[] lpImageBase,
            [In] uint cb,
            [Out] out uint lpcbNeeded);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool FreeLibrary(
            [In] UIntPtr hModule);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern IntPtr GetCurrentThread();
        /// <summary></summary>
        /// <param name="ImageBase"></param>
        /// <param name="lpFilename"></param>
        /// <param name="nSize"></param>
        /// <returns></returns>
        /// <remarks>See documentation on MSDN for reason of entry point renaming. Probably working since
        /// Windows 8 and later versions.</remarks>
        [DllImport("KERNEL32.DLL", EntryPoint = "K32GetDeviceDriverBaseName", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern uint GetDeviceDriverBaseNameA(
            [In] UIntPtr ImageBase,
            [In] IntPtr lpFilename,
            [In] int nSize);
        [DllImport("KERNEL32.DLL", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Ansi,
            SetLastError = true)]
        internal static extern IntPtr GetProcAddress(
            [In] IntPtr hModule,
            [In] string lpProcName);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(
            [In] IntPtr hModule,
            [In] ulong ordinal);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetProcessHeap();
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern unsafe void* HeapAlloc(
            [In] IntPtr hHeap,
            [In] uint dwFlags,
            [In] uint dwBytes);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool HeapFree(
            [In] IntPtr hHeap,
            [In] uint dwFlags,
            [In] UIntPtr lpMem);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(
            [In] string lpFileName);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern UIntPtr LoadLibraryExA(
            [In] string lpLibFileName,
            [In] IntPtr hFile,
            [In] uint dwFlags);
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr MapViewOfFile(
            [In] IntPtr hFileMappingObject,
            [In] uint dwDesiredAccess,
            [In] uint dwFileOffsetHigh,
            [In] uint dwFileOffsetLow,
            [In] ulong dwNumberOfBytesToMap);
        [DllImport("NTDLL.DLL", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern uint NtQuerySystemInformation(
            [In] uint /* SYSTEM_INFORMATION_CLASS */ SystemInformationClass,
            [In] UIntPtr SystemInformation,
            [In] uint SystemInformationLength,
            [Out] out uint ReturnLength);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern IntPtr OpenProcess(
            [In] uint dwDesiredAccess,
            [In] bool bInheritHandle,
            [In] uint dwProcessId);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern bool OpenProcessToken(
            [In] IntPtr ProcessHandle,
            [In] uint DesiredAccess,
            [Out] out IntPtr TokenHandle);
        [DllImport("SECHOST.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern unsafe IntPtr OpenTrace(
            [In] EVENT_TRACE_LOGFILE* Logfile);
        [DllImport("KERNEL32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32First(
            [In] IntPtr hSnapshot,
            [In] IntPtr /* LPPROCESSENTRY32 */ lppe);
        [DllImport("KERNEL32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool Process32Next(
            [In] IntPtr hSnapshot,
            [In] IntPtr /* LPPROCESSENTRY32 */ lppe);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern unsafe uint ProcessTrace(
            [In] IntPtr /* PTRACEHANDLE */ HandleArray,
            [In] uint HandleCount,
            [In] ulong* /* LPFILETIME */ StartTime,
            [In] ulong* /* LPFILETIME */ EndTime);
        [DllImport("GDI32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool RemoveFontResourceExW(
            [In] string name,
            [In] uint fl,
            [In] UIntPtr pdv);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern bool RevertToSelf();
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlAdjustPrivilege(
            [In] int Privilege,
            [In] bool EnablePrivilege,
            [In] bool IsThreadPrivilege,
            [Out] out bool PreviousValue);
        [DllImport("NTOSKRNL.EXE", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern void RtlInitUnicodeString(
            [In, Out] ref UNICODE_STRING DestinationString,
            [In] string SourceString);
        [DllImport("NTOSKRNL.EXE", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint TraceSetInformation(
            [In] IntPtr SessionHandle,
            [In] uint /* TRACE_INFO_CLASS */ InformationClass,
            [In] UIntPtr TraceInformation,
            [In] uint InformationLength);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool SetThreadPriority(
            [In] IntPtr hThread,
            [In] int nPriority);
        [DllImport("ADVAPI32.DLL", SetLastError = true)]
        internal static extern bool SetThreadToken(
            [In] IntPtr Thread,
            [In] IntPtr Token);
        [DllImport("SECHOST.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern unsafe uint StartTrace(
            [Out] out IntPtr /* PTRACEHANDLE */ SessionHandle,
            [In] string SessionName,
            [In] EVENT_TRACE_PROPERTIES* Properties);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool UnmapViewOfFile(
            [In] IntPtr lpBaseAddress);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern UIntPtr VirtualAlloc(
            [In] UIntPtr lpAddress,
            [In] ulong dwSize,
            [In] uint flAllocationType,
            [In] uint flProtect);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool VirtualFree(
            [In] UIntPtr lpAddress,
            [In] ulong dwSize,
            [In] uint dwFreeType);
        [DllImport("KERNEL32.DLL", SetLastError = true)]
        internal static extern bool WriteFile(
            [In] IntPtr hFile,
            [In] UIntPtr lpBuffer,
            [In] uint nNumberOfBytesToWrite,
            [Out] out uint lpNumberOfBytesWritten,
            [In] UIntPtr /* LPOVERLAPPED */ lpOverlapped        );
        [DllImport("NTOSKRNL.EXE", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern unsafe int ZwOpenSection(
            [Out] out IntPtr SectionHandle,
            [In] uint DesiredAccess,
            [In] OBJECT_ATTRIBUTES* ObjectAttributes);

        internal static readonly IntPtr InvalidHandle = new IntPtr(-1L);

        [StructLayout(LayoutKind.Explicit)]
        internal struct ETW_BUFFER_CONTEXT
        {
            // Start of struct
            [FieldOffset(0)]
            internal byte ProcessorNumber;
            [FieldOffset(1)]
            internal byte Alignment;
            // End of DUMMYSTRUCTNAME struct
            [FieldOffset(0)]
            internal ushort ProcessorIndex;
            [FieldOffset(2)]
            internal ushort LoggerId;
        }

        internal struct EVENT_DESCRIPTOR
        {
            internal ushort Id;
            internal byte Version;
            internal byte Channel;
            internal byte Level;
            internal byte Opcode;
            internal ushort Task;
            internal ulong Keyword;
        }

        // Sizeof is 80
        [StructLayout(LayoutKind.Explicit)]
        internal struct EVENT_HEADER
        {
            [FieldOffset(0)]
            internal ushort Size;
            [FieldOffset(2)]
            internal ushort HeaderType;
            [FieldOffset(4)]
            internal ushort Flags;
            [FieldOffset(6)]
            internal ushort EventProperty;
            [FieldOffset(8)]
            internal uint ThreadId;
            [FieldOffset(12)]
            internal uint ProcessId;
            [FieldOffset(16)]
            internal ulong TimeStamp;
            [FieldOffset(24)]
            internal Guid ProviderId;
            [FieldOffset(40)]
            internal EVENT_DESCRIPTOR EventDescriptor;
            // Start of struct
            [FieldOffset(56)]
            internal uint KernelTime;
            [FieldOffset(60)]
            internal uint UserTime;
            // End of struct
            [FieldOffset(56)]
            internal ulong ProcessorTime;
            [FieldOffset(64)]
            internal Guid ActivityId;
        }

        internal struct EVENT_HEADER_EXTENDED_DATA_ITEM
        {
            internal bool Linkage
            {
                get { return (0 != (_Linkage & 0x01)); }
            }

            internal ushort Reserved1;
            internal ushort ExtType;
            internal ushort _Linkage;
            internal ushort DataSize;
            internal ulong DataPtr;
        }

        internal unsafe struct EVENT_RECORD
        {
            internal EVENT_HEADER EventHeader;
            internal ETW_BUFFER_CONTEXT BufferContext;
            internal ushort ExtendedDataCount;
            internal ushort UserDataLength;
            internal EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData;
            internal void* UserData;
            internal void* UserContext;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct EVENT_TRACE
        {
            [FieldOffset(0)]
            internal EVENT_TRACE_HEADER Header;
            [FieldOffset(48)]
            internal uint InstanceId;
            [FieldOffset(52)]
            internal uint ParentInstanceId;
            [FieldOffset(56)]
            internal Guid ParentGuid;
            [FieldOffset(72)]
            internal UIntPtr MofData;
            [FieldOffset(80)]
            internal uint MofLength;
            [FieldOffset(84)]
            internal uint ClientContext;
            [FieldOffset(84)]
            internal ETW_BUFFER_CONTEXT BufferContext;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct EVENT_TRACE_HEADER
        {
            [FieldOffset(0)]
            internal ushort Size;
            [FieldOffset(2)]
            internal ushort FieldTypeFlags;
            [FieldOffset(2)]
            internal byte HeaderType;
            [FieldOffset(3)]
            internal byte MarkerFlags;
            [FieldOffset(4)]
            internal uint Version;
            // Class structure
            [FieldOffset(4)]
            internal byte Type;
            [FieldOffset(5)]
            internal byte Level;
            [FieldOffset(6)]
            internal ushort ClassVersion;
            // End of class structure
            [FieldOffset(8)]
            internal uint ThreadId;
            [FieldOffset(12)]
            internal uint ProcessId;
            [FieldOffset(16)]
            internal ulong TimeStamp;
            [FieldOffset(24)]
            internal Guid Guid;
            [FieldOffset(24)]
            internal UIntPtr GuidPtr;
            // Start of struct
            [FieldOffset(40)]
            internal uint ClientContext;
            [FieldOffset(44)]
            internal uint Flags;
            // End of struct
            // Start of struct
            [FieldOffset(40)]
            internal uint KernelTime;
            [FieldOffset(44)]
            internal uint UserTime;
            // End of struct
            [FieldOffset(40)]
            internal ulong ProcessorTime;
        }

        internal unsafe delegate void EventCallbackDelegate(EVENT_TRACE* pEvent);
        internal unsafe delegate void EventRecordCallbackDelegate(EVENT_RECORD* EventRecord);

        // Sizeof = 0x1C0
        [StructLayout(LayoutKind.Explicit)]
        internal struct EVENT_TRACE_LOGFILE
        {
            [FieldOffset(0)]
            internal UIntPtr LogFileName;
            [FieldOffset(8)]
            internal IntPtr LoggerName;
            [FieldOffset(16)]
            internal ulong CurrentTime;
            [FieldOffset(24)]
            internal uint BuffersRead;
            [FieldOffset(28)]
            internal uint LogFileMode;
            [FieldOffset(28)]
            internal uint ProcessTraceMode;
            [FieldOffset(32)]
            internal EVENT_TRACE CurrentEvent;
            [FieldOffset(0x78)]
            TRACE_LOGFILE_HEADER LogfileHeader;
            [FieldOffset(0x190)]
            internal UIntPtr /* PEVENT_TRACE_BUFFER_CALLBACK */ BufferCallback;
            [FieldOffset(0x198)]
            internal uint BufferSize;
            [FieldOffset(0x19C)]
            internal uint Filled;
            [FieldOffset(0x1A0)]
            internal uint EventsLost;
            [FieldOffset(0x1A8)]
            internal IntPtr /* PEVENT_CALLBACK ==> EventCallbackDelegate*/ EventCallback;
            [FieldOffset(0x1A8)]
            internal IntPtr /* PEVENT_RECORD_CALLBACK ==> EventRecordCallbackDelegate */ EventRecordCallback;
            [FieldOffset(0x1B0)]
            internal uint IsKernelTrace;
            [FieldOffset(0x1B8)]
            internal UIntPtr Context;
        }

        internal struct EVENT_TRACE_PROPERTIES
        {
            internal void Initialize()
            {
                Wnode.Initialize();
                MinimumBuffers = 0;
                MaximumBuffers = 0;
                MaximumFileSize = 0;
                LogFileMode = 0;
                FlushTimer = 0;
                EnableFlags = 0;
                AgeLimit = 0;
                NumberOfBuffers = 0;
                FreeBuffers = 0;
                EventsLost = 0;
                BuffersWritten = 0;
                LogBuffersLost = 0;
                RealTimeBuffersLost = 0;
                LoggerThreadId = IntPtr.Zero;
                LogFileNameOffset = 0;
                LoggerNameOffset = 0;
            }

            internal WNODE_HEADER Wnode;
            internal uint BufferSize;
            internal uint MinimumBuffers;
            internal uint MaximumBuffers;
            internal uint MaximumFileSize;
            internal uint LogFileMode;
            internal uint FlushTimer;
            internal uint EnableFlags;
            internal int AgeLimit;
            internal uint NumberOfBuffers;
            internal uint FreeBuffers;
            internal uint EventsLost;
            internal uint BuffersWritten;
            internal uint LogBuffersLost;
            internal uint RealTimeBuffersLost;
            internal IntPtr LoggerThreadId;
            internal uint LogFileNameOffset;
            internal uint LoggerNameOffset;
        }

        internal unsafe struct OBJECT_ATTRIBUTES
        {
            internal OBJECT_ATTRIBUTES(UNICODE_STRING* name, uint attributes, IntPtr rootDirectory, IntPtr securityDescriptor)
            {
                Length = 0;
                RootDirectory = rootDirectory;
                Attributes = attributes;
                ObjectName = name;
                SecurityDescriptor = securityDescriptor;
                SecurityQualityOfService = IntPtr.Zero;
                // Trick to have the compiler happy.
                Length = (uint)Marshal.SizeOf(this);
            }

            internal uint Length;
            internal IntPtr RootDirectory;
            internal UNICODE_STRING* ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        // Sizeof = 0x10
        internal struct SYSTEMTIME
        {
            internal ushort wYear;
            internal ushort wMonth;
            internal ushort wDayOfWeek;
            internal ushort wDay;
            internal ushort wHour;
            internal ushort wMinute;
            internal ushort wSecond;
            internal ushort wMilliseconds;
        }

        // Sizeof = 0xAC
        [StructLayout(LayoutKind.Explicit)]
        internal struct TIME_ZONE_INFORMATION
        {
            [FieldOffset(0)]
            internal int Bias;
            [FieldOffset(4)]
            internal char StandardName;
            [FieldOffset(0x44)]
            internal SYSTEMTIME StandardDate;
            [FieldOffset(84)]
            internal int StandardBias;
            [FieldOffset(88)]
            internal char DaylightName;
            [FieldOffset(152)]
            internal SYSTEMTIME DaylightDate;
            [FieldOffset(168)]
            internal int DaylightBias;
        }

        // Sizeof = 0x118
        [StructLayout(LayoutKind.Explicit)]
        internal struct TRACE_LOGFILE_HEADER
        {
            [FieldOffset(0)]
            internal uint BufferSize;
            [FieldOffset(4)]
            internal uint Version;
            // Start of struct
            [FieldOffset(4)]
            internal byte MajorVersion;
            [FieldOffset(5)]
            internal byte MinorVersion;
            [FieldOffset(6)]
            internal byte SubVersion;
            [FieldOffset(7)]
            internal byte SubMinorVersion;
            // End of VersionDetail struct;
            [FieldOffset(8)]
            internal uint ProviderVersion;
            [FieldOffset(12)]
            internal uint NumberOfProcessors;
            [FieldOffset(16)]
            internal ulong EndTime;
            [FieldOffset(24)]
            internal uint TimerResolution;
            [FieldOffset(28)]
            internal uint MaximumFileSize;
            [FieldOffset(32)]
            internal uint LogFileMode;
            [FieldOffset(36)]
            internal uint BuffersWritten;
            [FieldOffset(40)]
            internal Guid LogInstanceGuid;
            // Start of struct
            [FieldOffset(40)]
            internal uint StartBuffers;
            [FieldOffset(44)]
            internal uint PointerSize;
            [FieldOffset(48)]
            internal uint EventsLost;
            [FieldOffset(52)]
            internal uint CpuSpeedInMHz;
            // End of sqtruct
            [FieldOffset(56)]
            internal UIntPtr /* LPWSTR */ LoggerName;
            [FieldOffset(64)]
            internal UIntPtr /* LPWSTR */ LogFileName;
            [FieldOffset(72)]
            internal TIME_ZONE_INFORMATION TimeZone;
            // Alignment required.
            [FieldOffset(248)]
            internal ulong BootTime;
            [FieldOffset(256)]
            internal ulong PerfFreq;
            [FieldOffset(264)]
            internal ulong StartTime;
            [FieldOffset(272)]
            internal uint ReservedFlags;
            [FieldOffset(276)]
            internal uint BuffersLost;
        }

        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal UIntPtr Buffer;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct WNODE_HEADER
        {
            internal void Initialize()
            {
                BufferSize = 0;
                ProviderId = 0;
                HistoricalContext = 0;
                Version = 0;
                Linkage = 0;
                KernelHandle = IntPtr.Zero;
                TimeStamp = 0;
                Guid = Guid.Empty;
                ClientContext = 0;
                Flags = 0;
            }

            [FieldOffset(0)]
            internal uint BufferSize;
            [FieldOffset(4)]
            internal uint ProviderId;
            [FieldOffset(8)]
            internal ulong HistoricalContext;
            [FieldOffset(8)]
            internal uint Version;
            [FieldOffset(12)]
            internal uint Linkage;
            [FieldOffset(16)]
            internal IntPtr KernelHandle;
            [FieldOffset(16)]
            internal ulong TimeStamp;
            [FieldOffset(24)]
            internal Guid Guid;
            [FieldOffset(40)]
            internal uint ClientContext;
            [FieldOffset(44)]
            internal uint Flags;
        }
    }
}
