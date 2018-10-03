Function Get-CertificateByThumbprint
{
	# Define parameters
	Param(
	$Location,
	$StoreName, 
	$Thumbprint)

	# Check to see if store name exists
	if((Test-Path -Path "cert:\$Location\$($StoreName)"))
	{
		# Get the certificate
		return (Get-ChildItem -Path "cert:\$Location\$($StoreName)" | Where-Object {$_.Thumbprint -eq $Thumbprint})
	}
	else
	{
		return $null
	}
}

function Get-CertificateFileName
{
    # Define parameters
    Param ($Certificate)

$signature = @"
[DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool CertGetCertificateContextProperty(
    IntPtr pCertContext,
    uint dwPropId,
    IntPtr pvData,
    ref uint pcbData
);
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CRYPT_KEY_PROV_INFO {
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pwszContainerName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string pwszProvName;
    public uint dwProvType;
    public uint dwFlags;
    public uint cProvParam;
    public IntPtr rgProvParam;
    public uint dwKeySpec;
}
[DllImport("ncrypt.dll", SetLastError = true)]
public static extern int NCryptOpenStorageProvider(
    ref IntPtr phProvider,
    [MarshalAs(UnmanagedType.LPWStr)]
    string pszProviderName,
    uint dwFlags
);
[DllImport("ncrypt.dll", SetLastError = true)]
public static extern int NCryptOpenKey(
    IntPtr hProvider,
    ref IntPtr phKey,
    [MarshalAs(UnmanagedType.LPWStr)]
    string pszKeyName,
    uint dwLegacyKeySpec,
    uint dwFlags
);
[DllImport("ncrypt.dll", SetLastError = true)]
public static extern int NCryptGetProperty(
    IntPtr hObject,
    [MarshalAs(UnmanagedType.LPWStr)]
    string pszProperty,
    byte[] pbOutput,
    int cbOutput,
    ref int pcbResult,
    int dwFlags
);
[DllImport("ncrypt.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int NCryptFreeObject(
    IntPtr hObject
);
"@
Add-Type -MemberDefinition $signature -Namespace PKI -Name Tools

    $CERT_KEY_PROV_INFO_PROP_ID = 0x2 # from Wincrypt.h header file
    $cert = dir $certificate.PSPath
    $pcbData = 0
    [void] [PKI.Tools]::CertGetCertificateContextProperty($cert.Handle,$CERT_KEY_PROV_INFO_PROP_ID,[IntPtr]::Zero,[ref]$pcbData)
    $pvData = [Runtime.InteropServices.Marshal]::AllocHGlobal($pcbData)
    [void][PKI.Tools]::CertGetCertificateContextProperty($cert.Handle,$CERT_KEY_PROV_INFO_PROP_ID,$pvData,[ref]$pcbData)
    $keyProv = [Runtime.InteropServices.Marshal]::PtrToStructure($pvData,[type][PKI.Tools+CRYPT_KEY_PROV_INFO])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($pvData)
    $phProvider = [IntPtr]::Zero
    [void] [PKI.Tools]::NCryptOpenStorageProvider([ref]$phProvider,$keyProv.pwszProvName,0)
    $phKey = [IntPtr]::Zero
    [void] [PKI.Tools]::NCryptOpenKey($phProvider,[ref]$phKey,$keyProv.pwszContainerName,0,$keyProv.dwFlags)
    $pcbResult = 0
    [void] [PKI.Tools]::NCryptGetProperty($phKey,"Unique Name",$null,0,[ref]$pcbResult,0)
    $pbOutput = New-Object byte[] -ArgumentList $pcbResult
    [void][PKI.Tools]::NCryptGetProperty($phKey,"Unique Name",$pbOutput,$pbOutput.length,[ref]$pcbResult,0)
    $certificateFileName = [Text.Encoding]::Unicode.GetString($pbOutput)
    [void][PKI.Tools]::NCryptFreeObject($phProvider)
    [void][PKI.Tools]::NCryptFreeObject($phKey)
    
    # Return the file name, but remove the last character as it's unprintable
    return $certificateFileName = $certificateFileName.Substring(0, $certificateFileName.Length -1)
}


function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

		[System.String]
		$Ensure,

		[parameter(Mandatory = $true)]
		[System.String]
		$Location,

		[parameter(Mandatory = $true)]
		[System.String]
		$Store,

		[System.String]
		$UserAccount,

		[System.String]
		$Permission
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $returnValue = @{
    Ensure = [System.String]
    ServiceName = [System.String]
    BinDir = [System.String]
    Browser = [System.String[]]
    Credential = [System.Management.Automation.PSCredential]
    }

    $returnValue
    #>

	# Get reference to the certificate
	$certificate = Get-CertificateByThumbprint -Location $Location -StoreName $Store -Thumbprint $Thumbprint
	$fileName = $null

    # Store results
	if ($certificate)
	{
		# Check to see if it has a private key
		if ($certificate.HasPrivateKey)
		{
			# Check to see if private key is accessible
			if ($certificate.PrivateKey -ne $null)
			{
				# Assign filename
				$fileName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
			}
			else
			{
				# Get the filename
				$fileName = Get-CertificateFileName -Certificate $certificate
			}
		}

		# Get the full certificate path
		$certificateFile = Get-ChildItem -Path "c:\ProgramData\Microsoft\Crypto" | Where-Object {$_.Name -eq $fileName}
		
		# Get the acle
		$certAcl = Get-Acl -Path $certificateFile.FullName
	}
	$result= @{
		FriendlyName = $certificate.FriendlyName
		SerialNumber = $certificate.SerialNumber
		Thumbprint = $certificate.Thumbprint
		Access = $certAcl.Access
    }


    # return the results
    return $result
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

		[System.String]
		$Ensure,

		[parameter(Mandatory = $true)]
		[System.String]
		$Location,

		[parameter(Mandatory = $true)]
		[System.String]
		$Store,

		[System.String]
		$UserAccount,

		[System.String]
		$Permission
    )

	$certificate = Get-CertificateByThumbprint -Location $Location -StoreName $Store -Thumbprint $Thumbprint
	$fileName = $null

	if ($certificate)
	{
		# Check to see if it has a private key
		if ($certificate.HasPrivateKey)
		{
			# Check to see if private key is accessible
			if ($certificate.PrivateKey -ne $null)
			{
				# Assign filename
				$fileName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
			}
			else
			{
				# Get the filename
				$fileName = Get-CertificateFileName -Certificate $certificate
			}
		}

		# Get the full certificate path
		$certificateFile = Get-ChildItem -Path "c:\ProgramData\Microsoft\Crypto" -Recurse | Where-Object {$_.Name -eq $fileName}

		# Get the acle
		$certAcl = Get-Acl -Path $certificateFile.FullName
	}

	# Check to see if identity is present
	$accessRule = $certAcl.Access | Where-Object {$_.IdentityReference -eq $UserAccount}

	# Check ensure value
	switch ($Ensure)
	{
		"Present"
		{
			# Check a rule for the user already exists
			if ($accessRule)
			{
				# Remove the current access rule
				$certAcl.RemoveAccessRule($accessRule)
			}

			# Create access rule object
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $UserAccount, $Permission, Allow

			# Add the access rule
			$certAcl.AddAccessRule($accessRule)
		}
		"Absent"
		{
			# Remove the access rule
			$certAcl.RemoveAccessRule($accessRule)
		}
	}

	# Set the rule
	Set-Acl -Path $certificateFile.FullName -AclObject $certAcl
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

		[System.String]
		$Ensure,

		[parameter(Mandatory = $true)]
		[System.String]
		$Location,

		[parameter(Mandatory = $true)]
		[System.String]
		$Store,

		[System.String]
		$UserAccount,

		[System.String]
		$Permission
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

	# Get reference to the certificate
	$certificate = Get-CertificateByThumbprint -Location $Location -StoreName $Store -Thumbprint $Thumbprint
	$fileName = $null

	if ($certificate)
	{
		# Check to see if it has a private key
		if ($certificate.HasPrivateKey)
		{
			# Check to see if private key is accessible
			if ($certificate.PrivateKey -ne $null)
			{
				# Assign filename
				$fileName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
			}
			else
			{
				# Get the filename
				$fileName = Get-CertificateFileName -Certificate $certificate
			}
		}

		# Get the full certificate path
		$certificateFile = Get-ChildItem -Path "c:\ProgramData\Microsoft\Crypto" -Recurse | Where-Object {$_.Name -eq $fileName}

		# Get the acle
		$certAcl = Get-Acl -Path $certificateFile.FullName
	}

	# Declare working variables
    $desiredState = $true

	# Check to see if identity is present
	$accessRule = $certAcl.Access | Where-Object {$_.IdentityReference -eq $UserAccount}

	# Get enum value
	$enumValue = [System.Security.AccessControl.FileSystemRights] $Permission

	# Determine which path to take
    switch($Ensure)
    {
        "Present"
        {
			# Check to see if the user is in there
			if ($accessRule)
			{
				# Check the file system rights
				#if ($accessRule.FileSystemRights.ToString() -ne $Permission)
				
				if (!(($accessRule.FileSystemRights -band $enumValue) -eq $enumValue))
				{
					# Not in desired state
					$desiredState = $false
				}
			}
			else
			{
				# User is not present
				$desiredState = $false
			}
        }
        "Absent"
        {
			# Check for present
			if ($accessRule)
			{
				# Not in desired state
				$desiredState = $false
			}
        }
    }

    # Check for desired state
    if ($desiredState -and ($desiredState -eq $true))
    {
        # Display
        Write-Verbose "User permission for $UserName is in desired state, no action required"
        
        # return result
        return $true
    }
    else
    {
        # Display
        Write-Verbose "User permission for $UserName is not in desired state"

        # return result
        return $false
    }
}

 
Export-ModuleMember -Function *-TargetResource

