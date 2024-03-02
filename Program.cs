using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;

class Program
{
    // Import necessary Windows API functions
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    // Constants
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    // Structs
    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint SetNamedSecurityInfo(
         string pObjectName,
         SE_OBJECT_TYPE ObjectType,
         SECURITY_INFORMATION SecurityInfo,
         IntPtr psidOwner,
         IntPtr psidGroup,
         IntPtr pDacl,
         IntPtr pSacl);

    private enum SE_OBJECT_TYPE
    {
        SE_FILE_OBJECT = 1
    }

    [Flags]
    private enum SECURITY_INFORMATION
    {
        OWNER_SECURITY_INFORMATION = 0x00000001
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    static async Task Main(string[] args)
    {
        await ConnectAndCloseConnectionAsync("https://www.karma-x.io/hc_usage/");

        if (args.Length < 2)
        {
            Console.WriteLine("Usage: Program.exe <prependString> [operation]");
            Console.WriteLine("operation: apply - to prepend the string, undo - to remove the prepend string");
            return;
        }

        string prependString = args[0];
        string operation = args[1].ToLower();

        string[] filePaths = new string[]
        {
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
        };

        foreach (string originalPath in filePaths)
        {
            string directory = Path.GetDirectoryName(originalPath);
            string originalFileName = Path.GetFileName(originalPath);
            string newFileName;
            string newPath;
            string originalCurPath;

            if (operation == "apply")
            {
                newFileName = prependString + "_" + originalFileName;
                newPath = Path.Combine(directory, newFileName);
                originalCurPath = originalPath;
            }
            else if (operation == "undo")
            {
                newFileName = prependString + "_" + originalFileName;
                newPath = Path.Combine(directory, newFileName);
                string tmp1 = newFileName;
                string tmp2 = originalFileName;
                originalFileName = tmp1;
                newFileName = tmp2;
                tmp1 = originalPath;
                tmp2 = newPath;
                newPath = tmp1;
                originalCurPath = tmp2;
            }
            else
            {
                Console.WriteLine("Invalid operation specified. Use 'apply' to prepend or 'undo' to remove the prepend string.");
                return;
            }

            try
            {
                // Enable SeRestorePrivilege to change owner to TrustedInstaller
                EnablePrivilege("SeRestorePrivilege");

                // Change permissions and set ownership for the original file
                SetFileOwnerAndPermissions(originalCurPath);

                // Perform the file rename operation
                File.Move(originalCurPath, newPath);
                Console.WriteLine($"File successfully renamed from {originalFileName} to {newFileName}.");

                // Set the file owner to TrustedInstaller and adjust permissions
                SetFileOwnerToTrustedInstallerAndAdjustPermissions(newPath);

                RemoveAdminFullControlWriteModify(newPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while processing {originalFileName}: {ex.Message}");
            }
        }
    }

    static void SetFileOwnerAndPermissions(string filePath)
    {
        // Create a new FileInfo object
        FileInfo fileInfo = new FileInfo(filePath);

        // Get the current access control settings for the file
        FileSecurity fileSecurity = fileInfo.GetAccessControl();

        // Set the owner to the Administrators group
        IdentityReference adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        fileSecurity.SetOwner(adminSid);

        // Grant full control to the Administrators group
        fileSecurity.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));

        // Apply the updated access control settings to the file
        fileInfo.SetAccessControl(fileSecurity);
    }

    static void SetFileOwnerToTrustedInstallerAndAdjustPermissions(string filePath)
    {
        string trustedInstallerSidString = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        IntPtr trustedInstallerSid = IntPtr.Zero;
        if (!ConvertStringSidToSid(trustedInstallerSidString, out trustedInstallerSid))
        {
            Console.WriteLine("Failed to convert TrustedInstaller SID string to SID.");
            return;
        }

        // Attempt to change the file owner to TrustedInstaller
        uint result = SetNamedSecurityInfo(filePath, SE_OBJECT_TYPE.SE_FILE_OBJECT, SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION, trustedInstallerSid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            Console.WriteLine($"Failed to set file owner. Error: {result}");
        }
        else
        {
            Console.WriteLine("File owner changed to TrustedInstaller successfully.");
        }

        // Free the allocated memory for the SID
        if (trustedInstallerSid != IntPtr.Zero)
        {
            LocalFree(trustedInstallerSid);
        }
    }

    static void RemoveAdminFullControlWriteModify(string filePath)
    {
        // Create a new FileInfo object
        FileInfo fileInfo = new FileInfo(filePath);

        // Get the current access control settings for the file
        FileSecurity fileSecurity = fileInfo.GetAccessControl();

        // Identify the Administrators group
        IdentityReference adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        // Remove existing rules for the Administrators group
        AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference == adminSid)
            {
                // Remove existing rule
                fileSecurity.RemoveAccessRule(rule);
            }
        }

        // add specific permissions back 
        fileSecurity.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));

        // Apply the updated access control settings to the file
        fileInfo.SetAccessControl(fileSecurity);
    }

    static void EnablePrivilege(string privilege)
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES, out IntPtr tokenHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        if (!LookupPrivilegeValue(null, privilege, out LUID luid))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
        };

        if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        // Close the token handle
        CloseHandle(tokenHandle);
    }

    static async Task ConnectAndCloseConnectionAsync(string uri)
    {
        // simply tracking usage - feel free to share feedback!
        using (var httpClient = new HttpClient())
        {
            try
            {
                HttpResponseMessage response = await httpClient.GetAsync(uri);
            }
            catch (HttpRequestException e)
            {
                // Handle any errors that occurred during the request
                Console.WriteLine($"Request error: {e.Message}");
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);
}

