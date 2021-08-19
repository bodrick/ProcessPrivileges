# Process Privileges

Forked from: <http://processprivileges.codeplex.com/>

[LICENSE](LICENSE.md)

## Description

Privileges determine the type of system operations that a process can perform.

Process Privileges is a set of extension methods, written in C#, for System.Diagnostics.Process. It implements the functionality necessary to query, enable, disable or remove privileges on a process.

The following extension methods are offered:

* DisablePrivilege - _Disables the specified privilege on a process._
* EnablePrivilege - _Enables the specified privilege on a process._
* GetAccessTokenHandle - _Gets an access token handle for a process._
* GetPrivilegeAttributes - _Gets the attributes for a privilege on a process._
* GetPrivilegeState - _Gets the state of a privilege._
* GetPrivileges - _Gets the privileges and associated attributes from a process._
* RemovePrivilege - _Removes the specified privilege from a process._

In addition, a privilege enabler class is offered that enables privileges on a process in a safe way, ensuring that they are returned to their original state when an operation that requires a privilege completes.

## Background

For more information on privileges, see:

Privileges
[http://msdn.microsoft.com/en-us/library/aa379306.aspx](http://msdn.microsoft.com/en-us/library/aa379306.aspx)

Privilege Constants
[http://msdn.microsoft.com/en-us/library/bb530716.aspx](http://msdn.microsoft.com/en-us/library/bb530716.aspx)

## Guidance

Enabling a privilege allows a process to perform system-level actions that it could not previously.

Before enabling a privilege, many potentially dangerous, thoroughly verify that functions or operations in your code actually require them.

It is not normally appropriate to hold privileges that you enable for the lifetime of a process. Use sparingly; enable when needed, disable when not.

### Example 1: Safely Enabling a Privilege

```csharp
using System;
using System.Diagnostics;
using ProcessPrivileges;

internal static class PrivilegeEnablerExample
{
    public static void Main()
    {
        Process process = Process.GetCurrentProcess();

        using (new PrivilegeEnabler(process, Privilege.TakeOwnership))
        {
            // Privilege is enabled within the using block.
            Console.WriteLine(
                "{0} => {1}",
                Privilege.TakeOwnership,
                process.GetPrivilegeState(Privilege.TakeOwnership));
        }

        // Privilege is disabled outside the using block.
        Console.WriteLine(
            "{0} => {1}",
            Privilege.TakeOwnership,
            process.GetPrivilegeState(Privilege.TakeOwnership));
    }
}
```

```none
TakeOwnership => Enabled
TakeOwnership => Disabled
```

### Example 2: Using the Extension Methods

```csharp
using System;
using System.Diagnostics;
using System.Linq;
using ProcessPrivileges;

internal static class ProcessPrivilegesExample
{
    public static void Main()
    {
        // Get the current process.
        Process process = Process.GetCurrentProcess();

        // Get the privileges and associated attributes.
        PrivilegeAndAttributesCollection privileges = process.GetPrivileges();

        int maxPrivilegeLength = privileges.Max(privilege => privilege.Privilege.ToString().Length);

        foreach (PrivilegeAndAttributes privilegeAndAttributes in privileges)
        {
            // The privilege.
            Privilege privilege = privilegeAndAttributes.Privilege;

            // The privilege state.
            PrivilegeState privilegeState = privilegeAndAttributes.PrivilegeState;

            // Write out the privilege and its state.
            Console.WriteLine(
                "{0}{1} => {2}",
                privilege,
                GetPadding(privilege.ToString().Length, maxPrivilegeLength),
                privilegeState);
        }

        Console.WriteLine();

        // Privileges can only be enabled on a process if they are disabled.
        if (process.GetPrivilegeState(Privilege.TakeOwnership) == PrivilegeState.Disabled)
        {
            // Enable the TakeOwnership privilege on it.
            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.TakeOwnership);

            // Get the state of the TakeOwnership privilege.
            PrivilegeState takeOwnershipState = process.GetPrivilegeState(Privilege.TakeOwnership);

            // Write out the TakeOwnership privilege, its state and the result.
            Console.WriteLine(
                "{0}{1} => {2} ({3})",
                Privilege.TakeOwnership,
                GetPadding(Privilege.TakeOwnership.ToString().Length, maxPrivilegeLength),
                takeOwnershipState,
                result);
        }
    }

    private static string GetPadding(int length, int maxLength)
    {
        int paddingLength = maxLength - length;
        char[]() padding = new char[paddingLength](paddingLength);
        for (int i = 0; i < paddingLength; i++)
        {
            padding[i](i) = ' ';
        }

        return new string(padding);
    }
}
```

```none
ChangeNotify         => Enabled
Security             => Disabled
Backup               => Disabled
Restore              => Disabled
SystemTime           => Disabled
Shutdown             => Enabled
RemoteShutdown       => Disabled
TakeOwnership        => Disabled
Debug                => Enabled
SystemEnvironment    => Disabled
SystemProfile        => Disabled
ProfileSingleProcess => Disabled
IncreaseBasePriority => Disabled
LoadDriver           => Enabled
CreatePagefile       => Disabled
IncreaseQuota        => Enabled
Undock               => Enabled
ManageVolume         => Disabled
Impersonate          => Enabled
CreateGlobal         => Enabled

TakeOwnership        => Enabled (PrivilegeModified)
```

### Example 3: Reusing an Access Token Handle

```csharp
using System;
using System.Diagnostics;
using ProcessPrivileges;

internal static class ReusingAccessTokenHandleExample
{
    public static void Main()
    {
        // Access token handle reused within the using block.
        using (AccessTokenHandle accessTokenHandle =
            Process.GetCurrentProcess().GetAccessTokenHandle(
                TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query))
        {
            // Enable privileges using the same access token handle.
            AdjustPrivilegeResult backupResult = accessTokenHandle.EnablePrivilege(Privilege.Backup);
            AdjustPrivilegeResult restoreResult = accessTokenHandle.EnablePrivilege(Privilege.Restore);

            Console.WriteLine(
                "{0} => {1} ({2})",
                Privilege.Backup,
                accessTokenHandle.GetPrivilegeState(Privilege.Backup),
                backupResult);

            Console.WriteLine(
                "{0} => {1} ({2})",
                Privilege.Restore,
                accessTokenHandle.GetPrivilegeState(Privilege.Restore),
                restoreResult);
        }
    }
}
```

```none
Backup => Enabled (PrivilegeModified)
Restore => Enabled (PrivilegeModified)
```

## Privileges

| Privilege | Constant | Enum | Description | Support Baseline |
| :--- | :--- | :--- | :--- | :--- |
| SeAssignPrimaryTokenPrivilege | {"SE_ASSIGNPRIMARYTOKEN_NAME"} | Privilege.AssignPrimaryToken | _Replace a process-level token._ | Windows 2000 |
| SeAuditPrivilege | {"SE_AUDIT_NAME"} | Privilege.Audit | _Generate security audits._ | Windows 2000 |
| SeBackupPrivilege | {"SE_BACKUP_NAME"} | Privilege.Backup | _Back up files and directories._ | Windows 2000 |
| SeChangeNotifyPrivilege | {"SE_CHANGE_NOTIFY_NAME"} | Privilege.ChangeNotify |_Bypass traverse checking._| Windows 2000 |
| SeCreateGlobalPrivilege | {"SE_CREATE_GLOBAL_NAME"} | Privilege.CreateGlobal | _Create global objects._ | Windows 2000 SP4, Windows XP SP2 |
| SeCreatePagefilePrivilege | {"SE_CREATE_PAGEFILE_NAME"} | Privilege.CreatePageFile |_Create a pagefile._| Windows 2000 |
| SeCreatePermanentPrivilege | {"SE_CREATE_PERMANENT_NAME"} | Privilege.CreatePermanent | _Create permanent shared objects._ | Windows 2000 |
| SeCreateSymbolicLinkPrivilege | {"SE_CREATE_SYMBOLIC_LINK_NAME"} | Privilege.CreateSymbolicLink | _Create symbolic links._ | Windows 2000 |
| SeCreateTokenPrivilege | {"SE_CREATE_TOKEN_NAME"} | Privilege.CreateToken |_Create a token object._| Windows 2000 |
| SeDebugPrivilege | {"SE_DEBUG_NAME"} | Privilege.Debug |_Debug programs._|  Windows 2000 |
| SeEnableDelegationPrivilege | {"SE_ENABLE_DELEGATION_NAME"} | Privilege.EnableDelegation | _Enable computer and user accounts to be trusted for delegation._ | Windows 2000 |
| SeImpersonatePrivilege | {"SE_IMPERSONATE_NAME"} | Privilege.Impersonate | _Impersonate a client after authentication._ | Windows 2000 SP4, Windows XP SP2 |
| SeIncreaseBasePriorityPrivilege | {"SE_INC_BASE_PRIORITY_NAME"} | Privilege.IncreaseBasePriority | _Increase scheduling priority._ | Windows 2000 |
| SeIncreaseQuotaPrivilege | {"SE_INCREASE_QUOTA_NAME"} | Privilege.IncreaseQuota |_Adjust memory quotas for a process._| Windows 2000 |
| SeIncreaseWorkingSetPrivilege | {"SE_INC_WORKING_SET_NAME"} | Privilege.IncreaseWorkingSet |_Increase a process working set._| Windows 2000 |
| SeLoadDriverPrivilege | {"SE_LOAD_DRIVER_NAME"} | Privilege.LoadDriver | _Load and unload device drivers._ | Windows 2000 |
| SeLockMemoryPrivilege | {"SE_LOCK_MEMORY_NAME"} | Privilege.LockMemory |_Lock pages in memory._| Windows 2000 |
| SeMachineAccountPrivilege | {"SE_MACHINE_ACCOUNT_NAME"} | Privilege.MachineAccount | _Add workstations to domain._ | Windows 2000 |
| SeManageVolumePrivilege | {"SE_MANAGE_VOLUME_NAME"} | Privilege.ManageVolume |_Manage the files on a volume._| Windows 2000 |
| SeProfileSingleProcessPrivilege | {"SE_PROF_SINGLE_PROCESS_NAME"} | Privilege.ProfileSingleProcess |_Profile single process._| Windows 2000 |
| SeRelabelPrivilege | {"SE_RELABEL_NAME"} | Privilege.Relabel |_Modify an object label._| Windows 2000 |
| SeRemoteShutdownPrivilege | {"SE_REMOTE_SHUTDOWN_NAME"} | Privilege.RemoteShutdown | _Force shutdown from a remote system._ | Windows 2000 |
| SeRestorePrivilege | {"SE_RESTORE_NAME"} | Privilege.Restore | _Restore files and directories._ | Windows 2000 |
| SeSecurityPrivilege | {"SE_SECURITY_NAME"} | Privilege.Security | _Manage auditing and security log._ | Windows 2000 |
| SeShutdownPrivilege | {"SE_SHUTDOWN_NAME"} | Privilege.Shutdown | _Shut down the system._ | Windows 2000 |
| SeSyncAgentPrivilege | {"SE_SYNC_AGENT_NAME"} | Privilege.SyncAgent |_Synchronize directory service data._| Windows 2000 |
| SeSystemEnvironmentPrivilege | {"SE_SYSTEM_ENVIRONMENT_NAME"} | Privilege.SystemEnvironment | _Modify firmware environment values._ | Windows 2000 |
| SeSystemProfilePrivilege | {"SE_SYSTEM_PROFILE_NAME"} | Privilege.SystemProfile |_Profile system performance._| Windows 2000 |
| SeSystemtimePrivilege | {"SE_SYSTEMTIME_NAME"} | Privilege.SystemTime |_Change the system time._| Windows 2000 |
| SeTakeOwnershipPrivilege | {"SE_TAKE_OWNERSHIP_NAME"} | Privilege.TakeOwnership | _Take ownership of files or other objects._ | Windows 2000 |
| SeTcbPrivilege | {"SE_TCB_NAME"} | Privilege.TrustedComputerBase | _Act as part of the operating system._ | Windows 2000 |
| SeTimeZonePrivilege | {"SE_TIME_ZONE_NAME"} | Privilege.TimeZone |_Change the time zone._| Windows 2000 |
| SeTrustedCredManAccessPrivilege | {"SE_TRUSTED_CREDMAN_ACCESS_NAME"} | Privilege.TrustedCredentialManagerAccess |_Access Credential Manager as a trusted caller._| Windows 2000 |
| SeUndockPrivilege | {"SE_UNDOCK_NAME"} | Privilege.Undock |_Remove computer from docking station._| Windows 2000 |
| SeUnsolicitedInputPrivilege | {"SE_UNSOLICITED_INPUT_NAME"} | Privilege.UnsolicitedInput | _Read unsolicited input from a terminal device._ | Windows 2000 |

Related: _Process Token Privileges, [AdjustTokenPrivileges](http://msdn.microsoft.com/en-us/library/aa375202.aspx), [GetTokenInformation](http://msdn.microsoft.com/en-us/library/aa446671.aspx), [LookupPrivilegeName](http://msdn.microsoft.com/en-us/library/aa379176.aspx), [LookupPrivilegeValue](http://msdn.microsoft.com/en-us/library/aa379180.aspx), [LUID](http://msdn.microsoft.com/en-us/library/aa379261.aspx), [LUID_AND_ATTRIBUTES](http://msdn.microsoft.com/en-us/library/aa379263.aspx), [TOKEN_PRIVILEGES](http://msdn.microsoft.com/en-us/library/aa379630.aspx)_
