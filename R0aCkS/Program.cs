using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace R0aCkS
{
    internal class Program
    {
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
                Function = SymbolHandling.Lookup(moduleName, functionName);
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

        internal static unsafe void DumpHex(void* Data, ulong Size)
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

        private static bool IsPrintable(byte candidate)
        {
            return (Char.IsLetterOrDigit((char)candidate) || Char.IsPunctuation((char)candidate));
        }

        internal static unsafe int Main(string[] args)
        {
            ulong kernelValue;

            // Print header
            Console.WriteLine("r0aCkS v1.0.0 -- Ring 0 Army Knife");
            Console.WriteLine("Copyright (c) 2018 Alex Ionescu [@aionescu]");
            Console.WriteLine("http://www.windows-internals.com");
            Console.WriteLine();

            try {
                if (3 != args.Length) {
                    Console.WriteLine("USAGE: r0ak.exe");
                    Console.WriteLine("       [--execute <Address | module!function> <Argument>]");
                    Console.WriteLine("       [--write   <Address | module!function> <Value>]");
                    Console.WriteLine("       [--read    <Address | module!function> <Size>]");
                    return -1;
                }
                // Initialize symbol engine
                SymbolHandling.Initialize();
                // Initialize our execution engine
                try { ExecutionTracker.Setup(SymbolHandling.g_TrampolineFunction); }
                catch {
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
                        try { ExecutionTracker.Execute(kernelPointer, (UIntPtr)kernelValue); }
                        catch {
                            Console.WriteLine("[-] Failed to execute function");
                            throw;
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
                        try { ExecutionTracker.Read((void*)kernelPointer, (uint)kernelValue); }
                        catch {
                            Console.WriteLine("[-] Failed to read variable");
                            throw;
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
                        try { ExecutionTracker.Write((void*)kernelPointer, (uint)kernelValue); }
                        catch {
                            Console.WriteLine("[-] Failed to write variable");
                            throw;
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
                ExecutionTracker.Teardown();
            }
        }

        internal const uint SystemBigPoolInformation = 66;

        internal struct MODLOAD_DATA
        {
            internal uint ssize;
            internal uint ssig;
            internal IntPtr data;
            internal uint size;
            internal uint flags;
        }
    }
}
