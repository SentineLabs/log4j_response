import os
import sys
import hashlib
import re
import platform
import zipfile

################################################################################

## Globals.

#
# Global sets of log4j signatures of modules that have the vulnerability.
#
g_log4j_signatures_cve_2021_44228 = [
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
    # Hash for 2.6.2
    "00a91369f655eb1639c6aece5c5eb5108db18306",
    # Hash for 2.14.1
    "9141212b8507ab50a45525b545b39d224614528b"
]

g_log4j_signatures_cve_2021_45046 = [
    # Hash for 2.15.0
    "9bd89149d5083a2a3ab64dcc88b0227da14152ec",
    "ba55c13d7ac2fd44df9cc8074455719a33f375b9"
]
g_log4j_signatures_cve_2021_45105 = [
    # Hash for 2.16.0
    "539a445388aee52108700f26d9644989e7916e7c",
    "ca12fb3902ecfcba1e1357ebfc55407acec30ede"
]

#
# Output directory
#
g_default_output_dir = "/tmp/"
g_output_dir = g_default_output_dir

#
# Maximum hash file size in MB
#
g_hash_file_size = 10

#
# Maximum deep search file size in MB
#
g_default_ds_file_size = 30
g_ds_file_size = g_default_ds_file_size

#
# Global map that keeps track of the vulnerable files that were detected,
# these should usually be small in number.
#
# Type:
#   file_path -> {"method": detection_method, "sha1": signature}
#
g_results_map = {}

#
# Global array that holds any errors
#
g_errors_arr = []

#
# Global defining whether Deep Search should be used
#
g_use_ds = True

#
# Global defining whether to search in all files
#
g_search_binaries = False

#
# Global pre-compiled regex to search for the log4j string
#
g_regex_compiled_bytes = re.compile(b'log4j-core-2\\.([0-9]|1[0-6])(\\.[0-9]+)?(-beta9*)?\\.jar')
g_regex_compiled_str = re.compile('log4j-core-2\\.([0-9]|1[0-6])(\\.[0-9]+)?(-beta9*)?\\.jar')

################################################################################

## Function Definitions.
#
# This function outputs the log msg to stdout.
#
def write_log_output(s):
    g_errors_arr.append(s)

#
# This function captures the result of each detection for future output.
# file_path - file path of the detected vulnerability
# detection_method - this can be "name_match", "signature_match", or "deep_search"
# signature - this is only valid for "signature_match", and otherwise is "".
#
def capture_result_for_output(file_path, detection_method, signature, cve_ids, potentially=False):
    if file_path in g_results_map:
        write_log_output("(capture_result_for_output) already exists: {}".format(file_path + detection_method + signature))
        return
    g_results_map[file_path] = {'method': detection_method, 'sha1': signature, 'cve_ids': cve_ids, 'potentially': potentially}

#
# Filters key JSON characters
#
def filter_json_str(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\b", "\\b").replace("\f", "\\f").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

#
# Outputs the captured results.
#
def print_captured_results():
    machine_name = platform.node()
    os_version = platform.platform()
    final_json = ""
    # Generate json manually as to maintain support for Python 2.5
    found = []
    for k, v in g_results_map.items():
        cve_info = "This was found as potentially vulnerable to {}.".format(", ".join(v['cve_ids']))
        if v['potentially']:
            cve_info = "{} It was unable to differentiate between 2.15.0 and 2.16.0.".format(cve_info)
        found.append("{{\"file_path\":\"{}\",\"method\":\"{}\",\"sha1\":\"{}\",\"info\":\"{}\"}}".format(filter_json_str(k), filter_json_str(v['method']), filter_json_str(v['sha1']), cve_info))
    errors = ",".join(['"' + filter_json_str(i) + '"' for i in g_errors_arr])
    final_json = "{{\"MachineName\":\"{}\",\"OS_Version\":\"{}\",\"Found\":[{}],\"Errors\":[{}]}}".format(filter_json_str(machine_name), filter_json_str(os_version), ",".join(found), errors)
    print(final_json)
    with open(os.path.join(g_output_dir, "script_done.txt"), 'w') as f: pass
    if len(g_results_map) > 0:
        with open(os.path.join(g_output_dir, "s1_log4j_found.txt"), 'w') as f:
            f.write(final_json)
    else:
        with open(os.path.join(g_output_dir, "s1_log4j_not_found.txt"), 'w') as f: pass

#
# This represents a target file to scan.
#
class TargetFile:
    def __init__(self, file_path):
        self.file_path = file_path
        self.sha1sum = ""
        self.file_size = 0

    #
    # Obtains the sha1 hash of the file
    #
    def get_sha1_of_file(self):
        BUF_SIZE = 65536
        try:
            sha1 = hashlib.sha1()
            with open(self.file_path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha1.update(data)
        except Exception as e:
            write_log_output("Couldn't get sha1 of file {}. Error: {}".format(self.file_path, str(e)))
            return
        self.sha1sum = sha1.hexdigest()

    #
    # Checks whether the current signature exists in the list of known
    # vulnerable signatures
    #
    def log4j_vuln_signature_match(self):
        if self.sha1sum in g_log4j_signatures_cve_2021_44228:
            return ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105']
        elif self.sha1sum in g_log4j_signatures_cve_2021_45046:
            return ['CVE-2021-45046', 'CVE-2021-45105']
        elif self.sha1sum in g_log4j_signatures_cve_2021_45105:
            return ['CVE-2021-45105']
        return []

    #
    # Returns true if there exists a log4j-core version is between 2.0 and 2.16 inclusive.
    #
    def search_name(self, search_string=None, found_through="name_match"):
        global g_regex_compiled_bytes
        global g_regex_compiled_str
        if search_string is None:
            search_string = self.file_path
        is_bytes = type(search_string) == bytes
        try:
            # lib4j-core filename is of the form log4j-core-XXXX.jar.
            # Extract version string.
            match = (g_regex_compiled_bytes.search(search_string) if is_bytes else g_regex_compiled_str.search(search_string))
            if not match:
                return False
            # The version string can be of the form X.Y.Z or X.Y-tokenZ, where
            # X Y and Z are numbers, and token can be 'alpha', 'beta', or 'rc'.
            version_split = match.group(1).split(b"." if is_bytes else ".")
            # Parse the minor version differently based on the forms above.
            minor_ver = None
            if (is_bytes and b"-" in version_split[0]) or (not is_bytes and "-" in version_split[0]):
                minor_ver = int(version_split[0].split(b"-" if is_bytes else "-")[0])
            else:
                minor_ver = int(version_split[0])
            # Version numbers should never be 0
            if minor_ver < 0:
                write_log_output("({}) unable to parse version: {}".format(found_through, match.group(1)))
                return False
            if minor_ver <= 14:
                self.get_sha1_of_file()
                capture_result_for_output(self.file_path, found_through, self.sha1sum, ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'])
            elif minor_ver == 15:
                self.get_sha1_of_file()
                capture_result_for_output(self.file_path, found_through, self.sha1sum, ['CVE-2021-45046', 'CVE-2021-45105'])
            elif minor_ver == 16:
                self.get_sha1_of_file()
                capture_result_for_output(self.file_path, found_through, self.sha1sum, ['CVE-2021-45105'])
            return True
        except Exception as e:
            write_log_output("({}) unable to check name in file {}. Error: {}".format(found_through, self.file_path, str(e)))
            return False

    #
    # Currently this just checks the shasum of the file against known bad hashes,
    # and it then outputs the matches in the results file.
    #
    def find_by_hash(self):
        try:
            # NOTE: This logic only checks files with names of the form *.jar
            filename = os.path.basename(self.file_path).lower()
            if not (filename.endswith(".jar")):
                return False
            self.file_size = os.path.getsize(self.file_path)
            if self.file_size > g_hash_file_size * 1024 * 1024:
                return False
            self.get_sha1_of_file()
            if self.sha1sum:
                cve_ids = self.log4j_vuln_signature_match()
                if len(cve_ids) > 0:
                    capture_result_for_output(self.file_path, "signature_match", self.sha1sum, cve_ids)
                return True
        except Exception as e:
            write_log_output("(find_by_hash) unable to check path: {}. Error: {}".format(self.file_path, str(e)))
        return False
    
    #
    # If the file extension is .jar, using ZipFile is faster than loading the file
    # and parsing directly.
    #
    def find_by_zipfile(self):
        try:
            zip = zipfile.ZipFile(self.file_path, "r")
            for f in zip.namelist():
                if self.search_name(f, "zip_filename_match"):
                    return True
        except Exception as e:
            write_log_output("(find_by_zipfile) unable to check file: {}. Error: {}".format(self.file_path, str(e)))
        return False
    
    def search_file_contents(self, file_data):
        # 1) This is potentially a log4j file
        # 2) This is a log4j 2.x file
        # 3) This is not a log4j 2.17+ file
        # 4) Verify with additional classes that it is not a 2.17+ file
        if (b"log4j" in file_data
            # log4j 2.x
            and b"AbstractSocketManager.class" in file_data
            and b"LogEventPatternConverter.class" in file_data
            and b"SystemPropertiesLookup.class" in file_data
            and b"MarkerPatternConverter.class" in file_data):
            self.get_sha1_of_file()

            # log4j 2.15/2.16+
            if b"BasicAsyncLoggerContextSelector.class" in file_data:
                # log4j 2.17+
                if b"ConfigurationStrSubstitutor.class" in file_data:
                    return False
                capture_result_for_output(self.file_path, "deep_search", self.sha1sum, ['CVE-2021-45046', 'CVE-2021-45105'], potentially=True)
                return True
            capture_result_for_output(self.file_path, "deep_search", self.sha1sum, ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'])
            return True
        return False

    #
    # This function checks the extension of the file, the size of the file, and
    # the contents of the file to see that they are as expected for a vulnerable
    # version of log4j.
    #
    def find_by_ds(self):
        try:
            filename = os.path.basename(self.file_path).lower()
            extension = filename.split(".")[-1].lower()
            if not g_search_binaries and extension not in ["jar", "war", "ear", "zip"]:
                return False
            if self.file_size > g_ds_file_size * 1024 * 1024:
                return False
            
            # If it's a jar, try the fastpath using ZipFile
            if extension == "jar" and self.find_by_zipfile():
                return True

            # Begin the file search
            file_data = open(self.file_path, "rb").read()

            # Search file contents for known classes
            if self.search_file_contents(file_data):
                return True
            
            # Check whether there are any log4j-core filenames in this file:
            return self.search_name(file_data, "deep_search")
        except Exception as e:
            write_log_output("(find_by_ds) unable to check path: {}. Error: {}".format(self.file_path, str(e)))
        return False

    #
    # This function handles the filename scan, file hash scan, and the file scan.
    #
    def scan(self):
        global g_use_ds
        if self.find_by_hash():
            return True
        elif self.search_name():
            file_data = open(self.file_path, "rb").read()

            # If the filename is log4j-core-2.X.jar, it should have the right contents too.
            # Otherwise it could result in a false positive.
            return self.search_file_contents(file_data)
        elif g_use_ds and self.find_by_ds():
            return True
        return False


#
# This class performs the identification of files on the system.
# It excludes network fileshares in order to remain fast.
#
class FileFinder:
    def __init__(self, start_path, exclude_dirs):
        self.start_path = start_path
        self.exclude_dirs = exclude_dirs

    #
    # Scans a given file
    #
    def file_visit(self, file_path):
        target_file = TargetFile(file_path)
        target_file.scan()

    #
    # Traverses the file system visiting each file.
    #
    def traverse_fs(self):
        for path, dirs, files in os.walk(self.start_path, topdown=True):
            if len([dir for dir in self.exclude_dirs if (path + "/").startswith(dir)]) > 0:
                continue
            for file in files:
                f = os.path.join(path, file)
                if os.path.isfile(f):
                    self.file_visit(f)

    #
    # This function performs the file system scan.
    #
    def scan(self):
        self.traverse_fs()

#
# Find the list of mounted network file systems.
#
def get_nfs_mounts():
    mounts = []
    with open('/proc/mounts','r') as f:
        mounts = [{'fstype': line.split()[2], 'dir': line.split()[1]} for line in f.readlines()]
    excluded_dirs = []
    for mount in mounts:
        if mount['fstype'] in ["cifs"]:
            excluded_dirs.append(os.path.normpath(mount['dir']) + "/")
    return excluded_dirs

#
# In case the script was previously run, a cleanup may be required.
#
def clean():
    for f in [os.path.join(g_output_dir, "script_done.txt"),
            os.path.join(g_output_dir, "s1_log4j_found.txt"),
            os.path.join(g_output_dir, "s1_log4j_not_found.txt")]:
        try:
            os.remove(f)
        except Exception as e:
            return False

#
# In order to maintain compatibility for Python 2.5 and 2.6, we
# are unable to use argparse. Instead the function parseargs
# performs this for us.
#
def parseargs():
    global g_use_ds
    global g_ds_file_size
    global g_search_binaries
    global g_output_dir
    for arg in sys.argv[1:]:
        if arg.lower() == "--disable-deep-search":
            g_use_ds = False

        elif arg.lower().startswith("--deep-search-filesize="):
            try:
                g_ds_file_size = int(arg.split("=", 1)[1])
            except:
                return False

        elif arg.lower() == "--search-binaries":
            g_search_binaries = True

        elif arg.lower().startswith("--output-dir="):
            try:
                g_output_dir = arg.split("=", 1)[1]
            except:
                return False
        else:
            print("Unrecognized option: {}".format(arg))
            return False
    return True

#
# Prints the help for this program
#
def print_help():
    print("--disable-deep-search    - Disables deep search and resorts to using only hashes and filenames (Default: False)")
    print("--deep-search-filesize=N - Sets the largest size in megabytes of a file that this script will search in (Default: {})".format(g_default_ds_file_size))
    print("--search-binaries        - Sets whether the script will look in .jar files, or all files (Default: False)")
    print("--output-dir=XYZ         - Sets the output directory (Default: {})".format(g_default_output_dir))

#
# The main function
#
def main():
    # Verify this is run as root
    if os.geteuid() != 0:
        print("This script needs to be run as root")
        return -1
    
    # Check the version of Python
    ver = sys.version_info[0]
    if ver != 2 and ver != 3:
        print("Unsupported python version: " + str(ver))
        return -1
    
    # Parse supplied arguments
    if not parseargs():
        print_help()
        return -1
    
    # Make directories
    try:
        os.makedirs(g_output_dir)
    except Exception as e:
        # Is the directory already made and accessible to write?
        if not os.access(g_output_dir, os.W_OK):
            print("Unable to create " + g_output_dir)
            return -1
    
    # Clean any previously made files
    clean()

    # Get any cifs mounted folders
    exclude_dirs = get_nfs_mounts()

    # Add banned directories
    exclude_dirs += ["/dev/", "/proc/", "/sys/", "/boot/"]

    # Begin the file scan
    file_finder = FileFinder("/", exclude_dirs)
    file_finder.scan()

    # Output the results
    print_captured_results()
    return 0

################################################################################

## Entry Point.

if __name__ == '__main__':
    main()
