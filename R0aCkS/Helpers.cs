using System;
using System.Runtime.InteropServices;

namespace R0aCkS
{
    internal static class Helpers
    {
        static unsafe Helpers()
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

        internal delegate long RdtscDelegate();
        internal static readonly RdtscDelegate Rdtsc;
    }
}
