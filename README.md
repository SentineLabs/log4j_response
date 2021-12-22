# Visibility and Mitigation for Log4J vulnerabilities
Several scripts for the visibility and mitigation of Log4J vulnerabilities.
## Static Scanner - Linux
**How it works**\
The tool works by identifying files that are either vulnerable Log4J jars, or files containing potentially vulnerable Log4J jars. It uses a number of different methods to do this:
1. Name identification - This matches the name of the file with the vulnerable version range.
2. Hash identification - This performs hashing on the file and compares it with known hashes of vulnerable versions of Log4J.
3. Deep search identification - This searches for known classes within the vulnerable version range. If the file is zip-like, then the file names will be compared using name identification.

**Usage**\
--disable-deep-search - Disables deep search and resorts to using only hashes and filenames (Default: False)\
--deep-search-filesize=N - Sets the largest size in megabytes of a file that this script will search in (Default: 30)\
--search-binaries - Sets whether the script will look in .jar files, or all files (Default: False)\
--output-dir=XYZ - Sets the output directory (Default: /tmp/)\

**Example Output**
```
test@test:~$ sudo python log.py --search-binaries
{"MachineName":"test","OS_Version":"Linux-5.11.0-37-generic-x86_64-with-Ubuntu-20.04-focal","Found":[{"file_path":"/home/test/filename","method":"deep_search","sha1":"d1879ffaf40d4fa77d2dafb0163f91fefacefa06"}],"Errors":[]}
```

## Static Scanner - Windows
**How it works**\
The tool works by identifying files that are either vulnerable Log4J jars, or files containing potentially vulnerable Log4J jars. It uses a number of different methods to do this:
1. Hash identification - This performs hashing on the file and compares it with known hashes of vulnerable versions of Log4J.
2. Deep search identification - This searches for known classes within the vulnerable version range. If the file is zip-like, then the file names will be compared using name identification.

**Usage**\
Ivnoke-Log4JScan - This function scans the entire machine for potential Log4J vulnerable jar files.
-StringsLookup - If this parameter set to True, deep search indentification will be enabled

**Example Output**
```
PS > . .\invoke-log4jscan.ps1
PS > Ivnoke-Log4JScan -StringsLookup $True
{"Found" :[{"sha1" :"9ed084377e4396f3fe97a780610e3fd418813b83","method" :"deep_search","file_path" :"C:\\filename.jar"}],"MachineName" :"WIN-TEST","OS_Version" :"Windows_NT"}
```

```
PS > . .\invoke-log4jscan.ps1
PS > Ivnoke-Log4JScan -StringsLookup $True | Out-File $(join-path $env:temp 'log4j_scan_results.json')
```

## Dynamic Scanner And Patching - Windows & Linux
**How it works**  
We recommend using a great tool released this week by the Amazon Corretto team.  
A fork of the tool is included in this repo, with an added visibility feature that logs more info about possibly affected processes.  
It works by loading Java code into running Java processes using standard Java mechanisms.  
After being loaded into the processes, it detects if log4j is loaded and tries to do two things:
1. Log information about the module.  
2. Patch the vulnerable function.  
  
**Usage**  
Full instructions on building and running the tool is found in the [repository itself](https://github.com/SentineLabs/hotpatch-for-apache-log4j2).  




