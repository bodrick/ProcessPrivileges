using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessPrivileges
{
    internal static class Privileges
    {
        private const int PrivilegesCount = 35;

        private const string SeAssignPrimaryTokenPrivilege = "SeAssignPrimaryTokenPrivilege";
        private const string SeAuditPrivilege = "SeAuditPrivilege";
        private const string SeBackupPrivilege = "SeBackupPrivilege";
        private const string SeChangeNotifyPrivilege = "SeChangeNotifyPrivilege";
        private const string SeCreateGlobalPrivilege = "SeCreateGlobalPrivilege";
        private const string SeCreatePagefilePrivilege = "SeCreatePagefilePrivilege";
        private const string SeCreatePermanentPrivilege = "SeCreatePermanentPrivilege";
        private const string SeCreateSymbolicLinkPrivilege = "SeCreateSymbolicLinkPrivilege";
        private const string SeCreateTokenPrivilege = "SeCreateTokenPrivilege";
        private const string SeDebugPrivilege = "SeDebugPrivilege";
        private const string SeEnableDelegationPrivilege = "SeEnableDelegationPrivilege";
        private const string SeImpersonatePrivilege = "SeImpersonatePrivilege";
        private const string SeIncreaseBasePriorityPrivilege = "SeIncreaseBasePriorityPrivilege";
        private const string SeIncreaseQuotaPrivilege = "SeIncreaseQuotaPrivilege";
        private const string SeIncreaseWorkingSetPrivilege = "SeIncreaseWorkingSetPrivilege";
        private const string SeLoadDriverPrivilege = "SeLoadDriverPrivilege";
        private const string SeLockMemoryPrivilege = "SeLockMemoryPrivilege";
        private const string SeMachineAccountPrivilege = "SeMachineAccountPrivilege";
        private const string SeManageVolumePrivilege = "SeManageVolumePrivilege";
        private const string SeProfileSingleProcessPrivilege = "SeProfileSingleProcessPrivilege";
        private const string SeRelabelPrivilege = "SeRelabelPrivilege";
        private const string SeRemoteShutdownPrivilege = "SeRemoteShutdownPrivilege";
        private const string SeRestorePrivilege = "SeRestorePrivilege";
        private const string SeSecurityPrivilege = "SeSecurityPrivilege";
        private const string SeShutdownPrivilege = "SeShutdownPrivilege";
        private const string SeSyncAgentPrivilege = "SeSyncAgentPrivilege";
        private const string SeSystemEnvironmentPrivilege = "SeSystemEnvironmentPrivilege";
        private const string SeSystemProfilePrivilege = "SeSystemProfilePrivilege";
        private const string SeSystemTimePrivilege = "SeSystemtimePrivilege";
        private const string SeTakeOwnershipPrivilege = "SeTakeOwnershipPrivilege";
        private const string SeTcbPrivilege = "SeTcbPrivilege";
        private const string SeTimeZonePrivilege = "SeTimeZonePrivilege";
        private const string SeTrustedCredManAccessPrivilege = "SeTrustedCredManAccessPrivilege";
        private const string SeUndockPrivilege = "SeUndockPrivilege";
        private const string SeUnsolicitedInputPrivilege = "SeUnsolicitedInputPrivilege";

        private static readonly Dictionary<Privilege, Luid> LuidDictionary = new(PrivilegesCount);

        private static readonly Dictionary<Privilege, string> PrivilegeConstantsDictionary = new(PrivilegesCount)
        {
            { Privilege.AssignPrimaryToken, SeAssignPrimaryTokenPrivilege },
            { Privilege.Audit, SeAuditPrivilege },
            { Privilege.Backup, SeBackupPrivilege },
            { Privilege.ChangeNotify, SeChangeNotifyPrivilege },
            { Privilege.CreateGlobal, SeCreateGlobalPrivilege },
            { Privilege.CreatePageFile, SeCreatePagefilePrivilege },
            { Privilege.CreatePermanent, SeCreatePermanentPrivilege },
            { Privilege.CreateSymbolicLink, SeCreateSymbolicLinkPrivilege },
            { Privilege.CreateToken, SeCreateTokenPrivilege },
            { Privilege.Debug, SeDebugPrivilege },
            { Privilege.EnableDelegation, SeEnableDelegationPrivilege },
            { Privilege.Impersonate, SeImpersonatePrivilege },
            { Privilege.IncreaseBasePriority, SeIncreaseBasePriorityPrivilege },
            { Privilege.IncreaseQuota, SeIncreaseQuotaPrivilege },
            { Privilege.IncreaseWorkingSet, SeIncreaseWorkingSetPrivilege },
            { Privilege.LoadDriver, SeLoadDriverPrivilege },
            { Privilege.LockMemory, SeLockMemoryPrivilege },
            { Privilege.MachineAccount, SeMachineAccountPrivilege },
            { Privilege.ManageVolume, SeManageVolumePrivilege },
            { Privilege.ProfileSingleProcess, SeProfileSingleProcessPrivilege },
            { Privilege.Relabel, SeRelabelPrivilege },
            { Privilege.RemoteShutdown, SeRemoteShutdownPrivilege },
            { Privilege.Restore, SeRestorePrivilege },
            { Privilege.Security, SeSecurityPrivilege },
            { Privilege.Shutdown, SeShutdownPrivilege },
            { Privilege.SyncAgent, SeSyncAgentPrivilege },
            { Privilege.SystemEnvironment, SeSystemEnvironmentPrivilege },
            { Privilege.SystemProfile, SeSystemProfilePrivilege },
            { Privilege.SystemTime, SeSystemTimePrivilege },
            { Privilege.TakeOwnership, SeTakeOwnershipPrivilege },
            { Privilege.TrustedComputerBase, SeTcbPrivilege },
            { Privilege.TimeZone, SeTimeZonePrivilege },
            { Privilege.TrustedCredentialManagerAccess, SeTrustedCredManAccessPrivilege },
            { Privilege.Undock, SeUndockPrivilege },
            { Privilege.UnsolicitedInput, SeUnsolicitedInputPrivilege }
        };

        private static readonly Dictionary<string, Privilege> PrivilegesDictionary = new(PrivilegesCount)
        {
            { SeAssignPrimaryTokenPrivilege, Privilege.AssignPrimaryToken },
            { SeAuditPrivilege, Privilege.Audit },
            { SeBackupPrivilege, Privilege.Backup },
            { SeChangeNotifyPrivilege, Privilege.ChangeNotify },
            { SeCreateGlobalPrivilege, Privilege.CreateGlobal },
            { SeCreatePagefilePrivilege, Privilege.CreatePageFile },
            { SeCreatePermanentPrivilege, Privilege.CreatePermanent },
            { SeCreateSymbolicLinkPrivilege, Privilege.CreateSymbolicLink },
            { SeCreateTokenPrivilege, Privilege.CreateToken },
            { SeDebugPrivilege, Privilege.Debug },
            { SeEnableDelegationPrivilege, Privilege.EnableDelegation },
            { SeImpersonatePrivilege, Privilege.Impersonate },
            { SeIncreaseBasePriorityPrivilege, Privilege.IncreaseBasePriority },
            { SeIncreaseQuotaPrivilege, Privilege.IncreaseQuota },
            { SeIncreaseWorkingSetPrivilege, Privilege.IncreaseWorkingSet },
            { SeLoadDriverPrivilege, Privilege.LoadDriver },
            { SeLockMemoryPrivilege, Privilege.LockMemory },
            { SeMachineAccountPrivilege, Privilege.MachineAccount },
            { SeManageVolumePrivilege, Privilege.ManageVolume },
            { SeProfileSingleProcessPrivilege, Privilege.ProfileSingleProcess },
            { SeRelabelPrivilege, Privilege.Relabel },
            { SeRemoteShutdownPrivilege, Privilege.RemoteShutdown },
            { SeRestorePrivilege, Privilege.Restore },
            { SeSecurityPrivilege, Privilege.Security },
            { SeShutdownPrivilege, Privilege.Shutdown },
            { SeSyncAgentPrivilege, Privilege.SyncAgent },
            { SeSystemEnvironmentPrivilege, Privilege.SystemEnvironment },
            { SeSystemProfilePrivilege, Privilege.SystemProfile },
            { SeSystemTimePrivilege, Privilege.SystemTime },
            { SeTakeOwnershipPrivilege, Privilege.TakeOwnership },
            { SeTcbPrivilege, Privilege.TrustedComputerBase },
            { SeTimeZonePrivilege, Privilege.TimeZone },
            { SeTrustedCredManAccessPrivilege, Privilege.TrustedCredentialManagerAccess },
            { SeUndockPrivilege, Privilege.Undock },
            { SeUnsolicitedInputPrivilege, Privilege.UnsolicitedInput }
        };

        internal static AdjustPrivilegeResult DisablePrivilege(AccessTokenHandle accessTokenHandle, Privilege privilege) => AdjustPrivilege(accessTokenHandle, privilege, PrivilegeAttributes.Disabled);

        internal static AdjustPrivilegeResult EnablePrivilege(AccessTokenHandle accessTokenHandle, Privilege privilege) => AdjustPrivilege(accessTokenHandle, privilege, PrivilegeAttributes.Enabled);

        internal static PrivilegeAttributes GetPrivilegeAttributes(Privilege privilege, PrivilegeAndAttributesCollection privileges)
        {
            foreach (var privilegeAndAttributes in privileges)
            {
                if (privilegeAndAttributes.Privilege == privilege)
                {
                    return privilegeAndAttributes.PrivilegeAttributes;
                }
            }

            GetLuid(privilege);

            return PrivilegeAttributes.Removed;
        }

        internal static PrivilegeAndAttributesCollection GetPrivileges(AccessTokenHandle accessTokenHandle)
        {
            var luidAndAttributesArray = GetTokenPrivileges(accessTokenHandle);
            var length = luidAndAttributesArray.Length;
            var privilegeAndAttributes = new List<PrivilegeAndAttributes>(length);
            for (var i = 0; i < length; i++)
            {
                var luidAndAttributes = luidAndAttributesArray[i];
                var name = GetPrivilegeName(luidAndAttributes.Luid);
                if (PrivilegesDictionary.ContainsKey(name))
                {
                    privilegeAndAttributes.Add(new PrivilegeAndAttributes(
                        PrivilegesDictionary[name],
                        luidAndAttributes.Attributes));
                }
            }

            return new PrivilegeAndAttributesCollection(privilegeAndAttributes);
        }

        internal static AdjustPrivilegeResult RemovePrivilege(AccessTokenHandle accessTokenHandle, Privilege privilege) => AdjustPrivilege(accessTokenHandle, privilege, PrivilegeAttributes.Removed);

        private static AdjustPrivilegeResult AdjustPrivilege(AccessTokenHandle accessTokenHandle, Luid luid, PrivilegeAttributes privilegeAttributes)
        {
            var newState = new TokenPrivilege
            {
                PrivilegeCount = 1,
                Privilege = new LuidAndAttributes
                {
                    Attributes = privilegeAttributes,
                    Luid = luid
                }
            };
            var previousState = new TokenPrivilege();
            var returnLength = 0;

            if (!NativeMethods.AdjustTokenPrivileges(
                accessTokenHandle,
                false,
                ref newState,
                Marshal.SizeOf(previousState),
                ref previousState,
                ref returnLength))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return (AdjustPrivilegeResult)previousState.PrivilegeCount;
        }

        private static AdjustPrivilegeResult AdjustPrivilege(
            AccessTokenHandle accessTokenHandle,
            Privilege privilege,
            PrivilegeAttributes privilegeAttributes) => AdjustPrivilege(accessTokenHandle, GetLuid(privilege), privilegeAttributes);

        private static Luid GetLuid(Privilege privilege)
        {
            if (LuidDictionary.ContainsKey(privilege))
            {
                return LuidDictionary[privilege];
            }

            var luid = new Luid();
            if (!NativeMethods.LookupPrivilegeValue(string.Empty, PrivilegeConstantsDictionary[privilege], ref luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            LuidDictionary.Add(privilege, luid);
            return luid;
        }

        private static string GetPrivilegeName(Luid luid)
        {
            var nameBuilder = new StringBuilder();
            var nameLength = 0;
            if (NativeMethods.LookupPrivilegeName(string.Empty, ref luid, nameBuilder, ref nameLength))
            {
                return string.Empty;
            }

            var lastWin32Error = Marshal.GetLastWin32Error();
            if (lastWin32Error != NativeMethods.ErrorInsufficientBuffer)
            {
                throw new Win32Exception(lastWin32Error);
            }

            nameBuilder.EnsureCapacity(nameLength);
            if (!NativeMethods.LookupPrivilegeName(string.Empty, ref luid, nameBuilder, ref nameLength))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return nameBuilder.ToString();
        }

        private static LuidAndAttributes[] GetTokenPrivileges(AccessTokenHandle accessTokenHandle)
        {
            var tokenInformationLength = 0;
            var returnLength = 0;
            if (NativeMethods.GetTokenInformation(
                accessTokenHandle,
                TokenInformationClass.TokenPrivileges,
                IntPtr.Zero,
                tokenInformationLength,
                ref returnLength))
            {
                return Array.Empty<LuidAndAttributes>();
            }

            var lastWin32Error = Marshal.GetLastWin32Error();
            if (lastWin32Error != NativeMethods.ErrorInsufficientBuffer)
            {
                throw new Win32Exception(lastWin32Error);
            }

            tokenInformationLength = returnLength;
            returnLength = 0;

            using (var allocatedMemory = new AllocatedMemory(tokenInformationLength))
            {
                if (!NativeMethods.GetTokenInformation(
                    accessTokenHandle,
                    TokenInformationClass.TokenPrivileges,
                    allocatedMemory.Pointer,
                    tokenInformationLength,
                    ref returnLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var privilegeCount = Marshal.ReadInt32(allocatedMemory.Pointer);
                var luidAndAttributes = new LuidAndAttributes[privilegeCount];
                var pointer = allocatedMemory.Pointer.ToInt64() + Marshal.SizeOf(privilegeCount);
                var type = typeof(LuidAndAttributes);
                long size = Marshal.SizeOf(type);
                for (var i = 0; i < privilegeCount; i++)
                {
                    luidAndAttributes[i] = (LuidAndAttributes)Marshal.PtrToStructure(new IntPtr(pointer), type);
                    pointer += size;
                }

                return luidAndAttributes;
            }
        }
    }
}
