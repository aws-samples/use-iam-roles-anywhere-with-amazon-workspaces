# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

<#
 .SYNOPSIS
    This script configures "%userprofile%\.aws\config" file with custom configuration.

 .DESCRIPTION
    This script performs the following tasks:
    1. Defines a Log function to write logs to a file named IAMRolesAnywhereScript.log in path $env:USERPROFILE.
    2. Create a folder named UserCertificate in $env:USERPROFILE. Disables inheritence and set the permission for the current user.
    3. Checks for existing .pfx and .pem certificates in the specified path and deletes them if present.
    4. Exports the user's code-signing certificate to a .pfx file named pfxcertificate.pfx in the specified directory.
    5. Converts the exported .pfx certificate to a .pem file named pemcertificate.pem in the specified directory.
    6. Checks if the aws_signing_helper.exe tool is present in the specified awsSigningHelper path. If not, it downloads the tool from the provided URL.
    7. Generates the configuration for "%userprofile%\.aws\config" file
    8. Set the permission on private key for current user and disable inheritence on private key to secure the private key.

 .PARAMETER ProfileARN
    This required parameter is a string value for the the ARN of the Profile to pull the policies from.

 .PARAMETER RoleARN
    This required parameter is a string value for the ARN of the target role to assume.

 .PARAMETER TrustAnchorARN
    This required parameter is a string value for the ARN of the Trust anchor to use for authentication.

 .EXAMPLE
    assume-role.ps1  -ProfileARN "<Profile ARN>" -RoleARN "<Role ARN>" -TrustAnchorARN "<Trust Anchor ARN>"
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ProfileARN,
        [Parameter(Mandatory=$true)]
        [string]$RoleARN,
        [Parameter(Mandatory=$true)]
        [string]$TrustAnchorARN
    )

# Set Variables

$script:DirectoryPath = $null
$script:PFXPassword = $null
$script:PfxCert = $null
$script:PemCert = $null
$script:awsSigningHelperPath = $null
$script:FolderName = "UserCertificate"

function Set-DirectoryPath {
<#
 .SYNOPSIS
    Function to set the folder path to UserCertificate.
 .DESCRIPTION
    This function initializes the $script:DirectoryPath variable and set the value to UserCertificate and also initializes rest of the variable.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $FolderPath = Join-Path -Path $env:USERPROFILE -ChildPath $script:FolderName
    if ($PSCmdlet.ShouldProcess("Set directory path to $directoryPath")) {
        $script:DirectoryPath = $FolderPath
        Write-Log "Directory path set to $script:DirectoryPath"
        $script:PfxCert = "$script:DirectoryPath\pfxcertificate.pfx"
        $script:PemCert = "$script:DirectoryPath\pemcertificate.pem"
        $script:awsSigningHelperPath = "$script:DirectoryPath\aws_signing_helper.exe"
    }
}

function Write-Log {
<#
 .SYNOPSIS
    Define the logging function.
 .DESCRIPTION
    This function write the logs to a log file named $env:USERPROFILE\IAMRolesAnywhereScript.log.
    This function is called in other function for logging.
#>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    $logFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "IAMRolesAnywhereScript.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $logFilePath -Value $logEntry
    Write-Output $logEntry
}

function New-UserFolder {
<#
 .SYNOPSIS
    Function to create a folder in user profile.
 .DESCRIPTION
    This function creates a folder named UserCertificate in $env:USERPROFILE.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param ()

    if (-not (Test-Path $script:DirectoryPath)) {
        $createFolderMessage = "Creating folder '$script:FolderName' in $env:USERPROFILE"
        if ($PSCmdlet.ShouldProcess($createFolderMessage)) {
            try {
                New-Item -Path $script:DirectoryPath -ItemType Directory -ErrorAction Stop | Out-Null
                Write-Log "Folder '$script:FolderName' created successfully in $env:USERPROFILE"
            }
            catch {
                Write-Log "Failed to create folder '$FolderName' in $env:USERPROFILE"
            }
        }
    }
    else {
        Write-Log "Folder '$script:FolderName' already exists in $env:USERPROFILE"
    }
}

function Set-FolderPermission {
<#
 .SYNOPSIS
    Function to set the folder permission.
 .DESCRIPTION
    This function sets the UserCertificates folder NTFS permission and ownership to the current user and disable inheritence on the folder.
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param ()

    process {
        try {
            # Get the current user's identity
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

            # Get the current folder's ACL
            $acl = Get-Acl $script:DirectoryPath

            # Add the current user with full control permission
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")

            # Check if the user wants to proceed
            if ($PSCmdlet.ShouldProcess($script:DirectoryPath, "Add access rule for $currentUser")) {
                $acl.SetAccessRule($accessRule)
            }

            # Disable inheritance from the parent folder
            if ($PSCmdlet.ShouldProcess($script:DirectoryPath, "Disable inheritance")) {
                $acl.SetAccessRuleProtection($True, $False)
            }

            # Set folder owner to current owner
            if ($PSCmdlet.ShouldProcess($script:DirectoryPath, "Set owner to $currentUser")) {
                $acl.SetOwner([System.Security.Principal.NTAccount]($currentUser))
            }

            # Set the new ACL for the folder
            if ($PSCmdlet.ShouldProcess($script:DirectoryPath, "Set ACL")) {
                Set-Acl $script:DirectoryPath $acl
            }
        }
        catch {
            Write-Warning "Error setting permissions for folder: $script:DirectoryPath"
            Write-Warning $_.Exception.Message
        }
    }
}

function Remove-Certificate {
<#
 .SYNOPSIS
    Function to delete .pfx and .pem certificates.
 .DESCRIPTION
    This function checks if pemcertificate.pem and pfxcertificate.pfx certificate files are present in $env:USERPROFILE\UserCertificate folder and deletes then if they are present.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $pfxFile = Get-ChildItem -Path $script:PfxCert
    $pemFile = Get-ChildItem -Path $script:PemCert

    if ($pfxFile) {
        Write-Log "Deleting pfx certificate files..."
            if ($PSCmdlet.ShouldProcess($pfxFile.FullName, "Delete file")) {
                Remove-Item -Path $pfxFile -Force
            }
    }

    if ($pemFile) {
        Write-Log "Deleting pem certificate files..."
            if ($PSCmdlet.ShouldProcess($pemFile.FullName, "Delete file")) {
                Remove-Item -Path $pemFile -Force
            }
    }
}

function Export-UserCertificate {
<#
 .SYNOPSIS
    Function to export user certificate as .pfx format.
 .DESCRIPTION
    This function exports certifificate present in user certificate store to $env:USERPROFILE\UserCertificate folder in .pfx format along with the private key.
    It prompts the user to enter the password to password protect the private key.
#>
    try {
        # Get the user certificate from the personal certificate store
        $PFXcertificate = Get-ChildItem -Path Cert:\CurrentUser\My\ | Where-Object -Property PolicyId -Match -Value "pca-connector-ad"

        if ($PFXcertificate) {
            # Prompt the user for a password to protect the PFX file
            $script:PFXPassword = Read-Host -Prompt "Enter a password to protect the PFX file" -AsSecureString

            # Export the certificate to a PFX file
            $PFXcertificate | Export-PfxCertificate -FilePath $script:PfxCert -Password $script:PFXPassword

            Write-Log "Certificate exported successfully"
        }
        else {
            Write-Log "Certificate not found in the personal certificate store."
        }
    }
    catch {
        Write-Log "An error occurred while exporting the certificate: $($_.Exception.Message)"
    }
}

function Convert-PfxToPem {
<#
 .SYNOPSIS
    Function to convert .pfx to .pem
 .DESCRIPTION
    This function converts .pfx to .pem format using OpenSSL. The password required to convert the certificate to pem format is stored in $script:PFXPassword.
    OpenSSL should be added to the path variable which is a prerequisite.
    Password is clear from the variable and memory.
#>
    # Check if the OpenSSL command is available
    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
        throw "OpenSSL is not installed or not in the system PATH."
    }

    # Convert PFX to PEM
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:PFXPassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $openSSLCommand = openssl pkcs12 -in $script:PfxCert -nodes -passin pass:$Password -out $script:PemCert
    $openSSLCommand

    if ($LASTEXITCODE -eq 0) {
        Write-Log "PFX certificate successfully converted to PEM format and saved to $script:PemCert"
    } else {
        Write-Log "Failed to convert PFX certificate to PEM format."
    }
    Clear-Variable -Name Password
    Clear-Variable -Name PFXPassword
    [System.GC]::Collect()
}

function Get-AWSSigningHelperTool {
<#
 .SYNOPSIS
    Function to download aws_signing_helper.exe tool.
 .DESCRIPTION
    The function checks if the aws_signing_helper.exe is present and verify the hash and download if it's not present or there is a hash mismatch.
    Update the downloadUrl variable with correct URL as per public document. The download URL may change as newer versions are released.
    https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
    The function is also checking the hash of the file. If the hash of the file doesn't match with the $expectedhash the file is downloaded again.
#>
    $downloadUrl = "https://rolesanywhere.amazonaws.com/releases/1.1.1/X86_64/Windows/aws_signing_helper.exe"
    $expectedHash = "3fbed4f8c30a7718d919f885b004ef2d96a3fefab4249f90067dab183b648225" # Replace with the expected hash value

    if (Test-Path $script:awsSigningHelperPath) {
        Write-Log "aws_signing_helper.exe already exists, verifying file integrity..."
        $actualHash = (Get-FileHash -Path $script:awsSigningHelperPath -Algorithm SHA256).Hash
        if ($actualHash -eq $expectedHash) {
            Write-Log "File integrity verified."
        } else {
            Write-Log "File integrity check failed. Deleting the existing file and downloading again."
            Remove-Item -Path $script:awsSigningHelperPath -Force
            Invoke-WebRequest -Uri $downloadUrl -OutFile $script:awsSigningHelperPath
            $actualHash = (Get-FileHash -Path $script:awsSigningHelperPath -Algorithm SHA256).Hash
            if ($actualHash -eq $expectedHash) {
                Write-Log "File download and verification successful."
            } else {
                Write-Log "File download and verification failed. Unable to proceed."
                return
            }
        }
    } else {
        Write-Log "Downloading aws_signing_helper.exe..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $script:awsSigningHelperPath
        $actualHash = (Get-FileHash -Path $script:awsSigningHelperPath -Algorithm SHA256).Hash
        if ($actualHash -eq $expectedHash) {
            Write-Log "File download and verification successful."
        } else {
            Write-Log "File download and verification failed. Unable to proceed."
            return
        }
    }
}

function Set-AWSConfig {
<#
 .SYNOPSIS
    Function to configure "%userprofile%\.aws\config" file. 
 .DESCRIPTION
    The function defines the content of the "%userprofile%\.aws\config" file and will append the content in the existing config file.
    When making AWS API calls make sure to use the --profile parameter and specify the argument as iamrolesanywhere.
    Example:     
    aws sts get-caller-identity --profile iamrolesanywhere
    Get-STSCallerIdentity -ProfileName iamrolesanywhere

    You can specify a profile name of your own. For example: [profile WorkSpacesIAMRole]. Do not remove the 'profile' word before the actual profile name.
    Make sure to replace the regex pattern in line 350 depending the profile name you provide.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Create the ~/.aws/config file if it doesn't exist
    Write-Log "Create the ~/.aws/config file..."
    $configFilePath = Join-Path -Path $env:USERPROFILE -ChildPath ".aws\config"
    $configFileParentPath = Split-Path -Path $configFilePath -Parent

    if (-not (Test-Path -Path $configFileParentPath)) {
        if ($PSCmdlet.ShouldProcess($configFileParentPath, "Create directory")) {
            Write-Log "Creating directory: $configFileParentPath"
            New-Item -Path $configFileParentPath -ItemType Directory | Out-Null
        }
    }

    # Define the content of the config file
    $configContent = @"
[profile iamrolesanywhere]
credential_process = $script:awsSigningHelperPath credential-process --certificate $script:PemCert --private-key $script:PemCert --profile-arn $ProfileARN --role-arn $RoleARN --trust-anchor-arn $TrustAnchorARN
"@

    # Check if the config file exists
    if (Test-Path -Path $configFilePath) {
        # Read the existing config file content
        $existingConfigContent = Get-Content -Path $configFilePath -Raw

        # Remove the specific section from the existing config content
        $newConfigContent = $existingConfigContent -replace '(?s)\[profile iamrolesanywhere\].*?credential_process.*?\n', ''

        # Append the new config content
        $newConfigContent += $configContent

        # Write the updated config file content
        if ($PSCmdlet.ShouldProcess($configFilePath, "Set config file content")) {
            Write-Log "Setting config file content: $configFilePath"
            Set-Content -Path $configFilePath -Value $newConfigContent -Force
        }
    }
    else {
        # Write the content to the config file. This will create the file if it doesn't exist.
        if ($PSCmdlet.ShouldProcess($configFilePath, "Set config file content")) {
            Write-Log "Setting config file content: $configFilePath"
            Set-Content -Path $configFilePath -Value $configContent -Force
        }
    }
}

function Set-FilePermission {
<#
 .SYNOPSIS
    Function to set the permission on private key.
 .DESCRIPTION
    This function removes the NTFS permission for all the users except the current user and change the ownership of the private key to the current user.
 .PARAMETER File
    This required parameter is a string value for the pem file on which the permissions are set.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.IO.FileInfo]$File
    )
    process {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Get the current access control list (ACL) for the file
        $acl = Get-Acl -Path $File.FullName

        # Add permissions for the current user
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)

        # Remove all existing access rules except for the current user
        $acl.Access | Where-Object { $_.IdentityReference -ne $currentUser } | ForEach-Object {
            $shouldProcessMessage = "Removing access rule for '$($_.IdentityReference)' on file '$($File.FullName)'"
            if ($PSCmdlet.ShouldProcess($shouldProcessMessage)) {
                $acl.RemoveAccessRule($_)
            }
        }

        # Set the owner of the file to the current user
        $shouldProcessMessage = "Setting owner to '$currentUser' on file '$($File.FullName)'"
        if ($PSCmdlet.ShouldProcess($shouldProcessMessage)) {
            $acl.SetOwner([System.Security.Principal.NTAccount]$currentUser)
        }

        # Apply the modified ACL to the file
        $shouldProcessMessage = "Setting access control list on file '$($File.FullName)'"
        if ($PSCmdlet.ShouldProcess($shouldProcessMessage)) {
            Set-Acl -Path $File.FullName -AclObject $acl
        }
    }
}

function Disable-InheritanceOnFile {
<#
 .SYNOPSIS
    Function to disable inheritence on private key.
 .DESCRIPTION
    This function disables the inheritence on the private key to secure the key so that only the current user can access the key.
#>
    # Disable inheritance on the private key
    $acl = Get-Acl -Path $script:PemCert
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl -Path $script:PemCert -AclObject $acl

    Write-Log "Inheritance disabled on private key"
}

# Main function which call all the other functions.

function Main {
    Set-DirectoryPath
    New-UserFolder
    Set-FolderPermission
    Remove-Certificate
    Export-UserCertificate
    Convert-PfxToPem
    Get-AWSSigningHelperTool
    Set-FilePermission -File $script:PemCert
    Disable-InheritanceOnFile
    Set-AWSConfig
}

# Call the Main function

Main
