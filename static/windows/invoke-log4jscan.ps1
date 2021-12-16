# In order to support multiple .NET & Powershell versions (including Powershell 2.0). We need to declare and use 
# wide scope variables. There are no classes or static variables in most.

###########################
#
# Script Configuration
#
###########################

$script:Log4jSha1List = (
    "678861ba1b2e1fccb594bb0ca03114bb05da9695",
    "7621fe28ce0122d96006bdb56c8e2cfb2a3afb92",
    "4363cdf913a584fe8fa72cf4c0eaae181ef7d1eb",
    "2e8d52acfc8c2bbbaa7baf9f3678826c354f5405",
    "895130076efaf6dcafb741ed7e97f2d346903708",
    "13521c5364501478e28c77a7f86b90b6ed5dbb77",
    "31823dcde108f2ea4a5801d1acc77869d7696533",
    "c707664e020218f8529b9a5e55016ee15f0f82ac",
    "58a3e964db5307e30650817c5daac1e8c8ede648",
    "0d99532ba3603f27bebf4cdd3653feb0e0b84cf6",
    "a5334910f90944575147fd1c1aef9f407c24db99",
    "7ed845de1dfe070d43511fab321784e6c4118398",
    "a7cb258b9c36f49c148834a3a35b53fe73c28777",
    "2b557bf1023c3a3a0f7f200fafcd7641b89cbb83",
    "00a91369f655eb1639c6aece5c5eb5108db18306",
    "a3f2b4e64c61a7fc1ed8f1e5ba371933404ed98a",
    "2be463a710be42bb6b4831b980f0d270b98ff233",
    "4ac28ff2f1ddf05dae3043a190451e8c46b73c31",
    "979fc0cf8460302e4ffbfe38c1b66a99450b0bb7",
    "ff857555cec4635c272286a260dbd7979c89d5b8",
    "8c59f9db4e5eebf7e99aa0ed2eb129bd5d8ef4f8",
    "989bbd2b84eba4b88a4b2a889393fac5b297e1df",
    "3b1c23b9117786e23cc3be6224b484d77c50c1f2",
    "38b9c3790c99cef205a890db876c89fd9238706c",
    "5bcfefcd7474c2f439576a1839ea0aeeec07f3b6",
    "73fe23297ccf73bad25a04e089d9627f8bf3041f",
    "c28f281548582ec68376e66dbde48be24fcdb457",
    "ef568faca168deee9adbe6f42ca8f4de6ca4557b",
    "5eb5ab96f8fc087135ef969ed99c76b64d255d44",
    "16f7b2f63b0290281294c2cbc4f26ba32f71de34",
    "6556d71742808e4324eabc500bd7f2cc8c004440",
    "94bc1813a537b3b5c04f9b4adead3c434f364a70",
    "c476bd8acb6e7e55f14195a88fa8802687fcf542",
    "e7dc681a6da4f2f203dccd1068a1ea090f67a057",
    # Hash for 2.14.1
    "9141212b8507ab50a45525b545b39d224614528b",
    # Hash for 2.6.2
    "00a91369f655eb1639c6aece5c5eb5108db18306"
)


# Strings that are relevant for all log4j versions
$script:InclusionStrings = @(
    "log4j",
    "AbstractSocketManager.class",
    "LogEventPatternConverter.class",
    "SystemPropertiesLookup.class",
    "MarkerPatternConverter.class"
)

# Strings that are relevant for invulnerable log4j versions
$script:ExclusionStrings = @(
    "SelectArbiter.class",
    "ScriptArbiter.class",
    "BasicAsyncLoggerContextSelector.class"
)

# We scan only Java relevant extensions, make sure the strings are lowercase.
$script:FileExtensionsToScan = @(".jar", ".war", ".ear")

# Limit for max file size to scan
$script:StringsLookupMaxFileSize = 30 * 1024 * 1024

# The given hashes from the list are usually smaller than 10MB
$script:HashComparisonMaxFileSize = 10 * 1024 * 1024


###########################
#
# Shared & global variables
#
###########################


# This provider is used often so we better use it as a script scope vraiable
$script:SHA1CryptoServiceProvider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider;

# In order to search for strings in bytes arrays we - we convert them to latin1 encoding string.
# This encoder is being used often so we better use it as a script scope vraiable
$script:Latin1Encoder = [System.Text.Encoding]::GetEncoding('iso-8859-1')

# This Variable will store all the results from every drive, we find in order to return them as a JSON
$script:FullResults = @{
    'MachineName' = $env:COMPUTERNAME;
    'OS_Version' = $env:os;
    'Found' = @()
}

function Get-Sha1 {

    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Byte[]]
        $FileBytes
    )

    $Hash = ''
    
    try {
        $Hash = [System.BitConverter]::ToString($script:SHA1CryptoServiceProvider.ComputeHash($FileBytes)).replace("-", "").tolower();
    }
    catch {}

    return $Hash
}

function Invoke-FileScan {
    
    Param
    (
        $File,
        [Parameter(Mandatory=$False)]
        [Bool]
        $StringsLookup = $False
    )

    $Result = @{"file_path"=$file.FullName}

    if ($File.Length -le 0 -and $File.Length -gt $script:StringsLookupMaxFileSize -and $file.Length -gt $script:HashComparisonMaxFileSize){
        # We return here if we can, in order to avoid reading large files, or empty files.
        return
    }

    $FileBytes = $Null

    try
    {
        $FileBytes = [system.io.file]::readAllBytes($File.FullName)
    } catch {}

    if ($FileBytes) {
        $FileSha1 = $Null

        if ($File.Length -le $script:HashComparisonMaxFileSize) {
            $FileSha1 = Get-Sha1 -FileBytes $FileBytes
            if ($FileSha1 -and $script:Log4jSha1List -contains $FileSha1) {
                $Result.add('sha1', $FileSha1)
                $Result.add('method', 'signature_match')
                $script:FullResults.Found += $Result
                return
            }
        }

        if ($StringsLookup -and $File.Length -le $script:StringsLookupMaxFileSize) {            
            if (Invoke-StringsLookup -FileBytes $FileBytes){
                # If the hash wasn't calculated yet, calculate it now
                if ($FileSha1 -eq $Null) {
                    $FileSha1 = Get-Sha1 -FileBytes $FileBytes
                }
                $Result.add('sha1', $FileSha1)
                $Result.add('method', 'deep_search')
                $script:FullResults.Found += $Result
                return
            }
        }
    }
}

function Invoke-StringsLookup {

    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Byte[]]
        $FileBytes
    )

    # This converion is made in order to search for a string in a binary array.
    $searchableString = $script:Latin1Encoder.GetString($FileBytes);

    # Check if any of the InclusionStrings is missing
    ForEach ($string in $script:InclusionStrings){
        if ($searchableString.IndexOf($string) -lt 0){
            return $False
        }
    }

    # Check if any of the ExclusionStrings exists
    ForEach ($string in $script:ExclusionStrings){
        if ($searchableString.IndexOf($string) -ge 0){
            return $False
        }
    }

    return $True
}

function Invoke-DriveLog4JScan {

    Param (
        [Parameter(Mandatory=$True)]
        $Drive,
        [Parameter(Mandatory=$False)]
        [Bool]
        $StringsLookup = $False
    )

    # For some reason, when using -include to filter extension, Powershell might throw exception and stop the file iteration.
    get-childitem -path $Drive.Root -recurse -force -erroraction silentlycontinue | foreach-object {
        if ($_.PSIsContainer -eq $False) {
            if ($script:FileExtensionsToScan -contains $_.Extension.ToLower()){
                Invoke-FileScan -File $_ -StringsLookup $StringsLookup
            }
        }
    }
}

function Escape-JSONString {
    
    # Supports our specific results format, this function doesn't support integer, etc...
    # There are easier ways to serialize JSON in Powershell but they don't support any Powershell & .NET version

    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        $InputString
    )

    if ($InputString) {
        $EscapeStrings = @{
            '"' = '\"';
            "`n" = '\n';
            "`r" = '\r';
            "`t" = '\t';
            "`b" = '\b';
        }
        

        # In order to avoid escaping backslashes that were added to the string as a result
        # of another character escape, we need to make sure to escape backslash first.

        $InputString = $InputString.ToString().Replace('\','\\')

        $EscapeStrings.GetEnumerator() | ForEach-Object {
            $InputString = $InputString.Replace($_.Key, $_.Value)
        }

        return $InputString
    }
    return "";
}

function ConvertTo-JSON {

    # Supports our specific results format, this function doesn't support integer, etc...
    # There are easier ways to serialize JSON in Powershell but they don't support any Powershell & .NET version

    Param
    (
        [Parameter(ValueFromPipeline = $true)]
        $data=@()
    )
    $OutPutString = '{'
    $data.GetEnumerator() | ForEach-Object {
        if ($OutPutString -ne '{'){
            $OutPutString += ','
        }
        $OutPutString += '"'
        $OutPutString += Escape-JSONString $_.Key
        $OutPutString += '" :'
        if ($_.Value.GetType() -eq [object[]]){
            $ArrString = '['
            $_.Value.GetEnumerator() | ForEach-Object {
                if ($ArrString -ne '['){
                    $ArrString += ','
                }
                $ArrString += ConvertTo-JSON -data $_
            }
            $ArrString += ']'
            $OutPutString += $ArrString
        }
        else {
            $OutPutString += '"'
            $OutPutString += Escape-JSONString $_.Value
            $OutPutString += '"'
        }
    }
    $OutPutString += '}'
    return $OutPutString
}

function Invoke-Log4JScan {    
    <#
        .DESCRIPTION
        Scan the computer for vulnerable versions of log4j, based on hashes we collected and strings that
        should be inside the file. This method should find non-log4j packed jar files that contains log4j jar inside them.
        The function will return a JSON string with the reulsts, OS and hostname formatted.

        .PARAMETER StringsLookup
        Bollean, determine weather to scan strings inside the binary as well.
        
        .EXAMPLE
        Ivnoke-Log4JScan -StringsLookup $True

    #>
    Param (
        [Parameter(Mandatory=$False)]
        [Bool]
        $StringsLookup = $False
    )
    # Checking only local drives, and that the drives have files in them to ignore unnecessary drives like empty CD Drives.
    $Drives = Get-PSDrive | where {$_.Provider -match "FileSystem" -and $_.Used -gt 0}
    Foreach ($Drive in $Drives) {
        Invoke-DriveLog4JScan -Drive $Drive -StringsLookup $StringsLookup
    }
    
    return $($script:FullResults | ConvertTo-JSON)
}