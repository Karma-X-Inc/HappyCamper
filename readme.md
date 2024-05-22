# HappyCamper

HappyCamper is a tool designed for system administrators to enhance the security of Living off the Land Binaries (LoLBins) within enterprise environments. It allows administrators to prepend a unique "password" (in the form of a prepend string) to critical system binaries such as PowerShell, thereby requiring explicit knowledge of this modified name for execution. This mechanism aims to add an additional layer of security by potentially thwarting attackers' attempts to utilize these binaries for malicious purposes.

## ⚠️ Warning

HappyCamper manipulates critical system binaries by renaming them. This operation carries significant risks and could impact system stability, security, and functionality. **It is strongly advised that HappyCamper is used strictly for Research & Development (R&D) environments only.** Under no circumstances should HappyCamper be deployed in a production environment without thorough testing and a complete understanding of its implications.

### Key Features

- **Binary Renaming**: Allows for the renaming of specified system binaries, adding a unique identifier (prepend string) to the binary name.
- **Selective Access**: Only users or processes aware of the modified binary name can execute it, adding an extra layer of security against unauthorized use.
- **Undo Functionality**: Provides the capability to revert changes, restoring binaries to their original names.

### Usage

To use HappyCamper, run the program with the desired prepend string and specify the operation mode (`apply` or `undo`). The `apply` operation will prepend the specified string to the binary names, while `undo` will remove this prepend string, restoring the original names.

```plaintext
Usage: HappyCamper.exe <prependString> [operation]
    
    operation: 
        apply - to prepend the string, 
        undo - to remove the prepend string
```

##### Edit Registry

Take a look at candidate registry locations on your system for potential places you can restore system functionality that may have broken.  It all depends on how YOU want your system to behave and whether you want to be at risk of an attacker enumerating the location.  Play around, don't let anybody tell you shouldn't manage your system how you want to.  Simply putting Windows on a D: drive will break some "sophisticated attacks" with buggy code that hardcodes the D: drive.  Happy Camping!
        
#### Example

Applying the prepend string "abc123" to PowerShell binaries:

```shell
HappyCamper.exe abc123 apply
```

Undoing the changes:

```shell
HappyCamper.exe abc123 undo
```


### Supported Binaries

HappyCamper currently supports the following system binaries:

powershell.exe
powershell_ise.exe
More binaries can be added to the filePaths array within the program code as required.

### ⚠️ Important Considerations
**System Impact**: Renaming critical binaries might break scripts, applications, or system functionalities that rely on these binaries' default paths and names.
Security: While renaming binaries can deter unsophisticated attackers, it is not a foolproof security measure. Skilled attackers may still identify and utilize the renamed binaries.
**No Warranty**: HappyCamper is provided "as is", without warranty of any kind. The developers are not responsible for any damage or loss resulting from its use.
**Contribution**
Contributions to HappyCamper are welcome, especially in expanding its binary support, improving its safety checks, or enhancing its security features. Please fork the repository, make your changes, and submit a pull request for review.

#### License
HappyCamper is distributed under the MIT License. See the LICENSE file in the project repository for more information.

#### Disclaimer
This tool is for demonstration purposes only and should be used with caution. The developers of HappyCamper assume no liability for any misuse of the tool or any damage that may occur from its use. Always ensure backups are in place before attempting to modify system binaries.
