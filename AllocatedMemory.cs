using System;
using System.Runtime.InteropServices;

namespace ProcessPrivileges
{
    internal sealed class AllocatedMemory : IDisposable
    {
        internal AllocatedMemory(int bytesRequired) => Pointer = Marshal.AllocHGlobal(bytesRequired);

        ~AllocatedMemory() => InternalDispose();

        internal IntPtr Pointer { get; private set; }

        public void Dispose()
        {
            InternalDispose();
            GC.SuppressFinalize(this);
        }

        private void InternalDispose()
        {
            if (Pointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Pointer);
                Pointer = IntPtr.Zero;
            }
        }
    }
}
