using System.Runtime.InteropServices;

namespace ProcessPrivileges
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid
    {
        internal int LowPart;

        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LuidAndAttributes
    {
        internal Luid Luid;

        internal PrivilegeAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenPrivilege
    {
        internal int PrivilegeCount;

        internal LuidAndAttributes Privilege;
    }
}
