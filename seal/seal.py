#!/usr/bin/python2
#
# Copyright 2015 Filippo Bonazzi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""The SELinux Analytics Library"""

from policy import Policy, Context
from collections import defaultdict
import argparse
from subprocess import check_output, check_call, CalledProcessError
import readline
import tempfile
import os
import sys
import re
import shlex

adb = "adb"
processes_on_device_no = 0
files_on_device_no = 0

class FileOnDevice(object):
    """Class providing an abstraction for a file on the device"""
    file_class_converter = {'-': 'file',        'file':         '-', # File
                            'd': 'dir',         'dir':          'd', # Directory
                            'c': 'chr_file',    'chr_file':     'c', # Character device
                            'l': 'lnk_file',    'lnk_file':     'l', # Symlink
                            'p': 'fifo_file',   'fifo_file':    'p', # Named pipe
                            's': 'sock_file',   'sock_file':    's', # Socket
                            'b': 'blk_file',    'blk_file':     'b'} # Block device

    correct_line = ('[-dclpsb][-rwxst]{9}\\s+[^\\s]+\\s+[^\\s]+\\s+[^\\s:]+:[^\\s:]+:[^\\s:]+:[^\\s:]+\\s+.*')

    def __init__(self, l, d):
        if not re.match(FileOnDevice.correct_line, l):
            raise Exception('Bad file "{}"'.format(l))
        line = l.split(None, 4)
        self._security_class = FileOnDevice.file_class_converter[line[0][0]]
        self._dac = line[0]
        self._user = line[1]
        self._group = line[2]
        self._context = Context(line[3])
        if self._security_class == "lnk_file" and "->" in line[4]:
            # If it is a symlink it has a target
            self._basename = line[4].split(" -> ")[0]
            self._target = line[4].split(" -> ")[1]
        else:
            self._basename = line[4]
        self._path = d
        self._absname = os.path.join(self._path, self._basename)

    @property
    def security_class(self):
        """Get the file class"""
        return self._security_class

    @property
    def dac(self):
        """Get the file DAC permission string"""
        return self._dac

    @property
    def user(self):
        """Get the file DAC user"""
        return self._user

    @property
    def group(self):
        """Get the file DAC group"""
        return self._group

    @property
    def context(self):
        """Get the file SELinux context"""
        return self._context

    @property
    def basename(self):
        """Get the file basename"""
        return self._basename

    @property
    def target(self):
        """If the file is a symlink, get the link target"""
        if self._security_class == "lnk_file":
            return self._target
        else:
            return None

    @property
    def path(self):
        """Get the file path"""
        return self._path

    @property
    def absname(self):
        """Get the file absolute name"""
        return self._absname

    def is_symlink(self):
        """Returns True if the file is a symlink, False otherwise"""
        if self._security_class == "lnk_file":
            return True
        else:
            return False

    def is_directory(self):
        """Returns True if the file is a directory, False otherwise"""
        if self._security_class == "dir":
            return True
        else:
            return False

    def __repr__(self):
        return self.absname

    def __eq__(self, other):
        if self._absname == other._absname:
            return True
        else:
            return False

    def __lt__(self, other):
        if self._absname < other._absname:
            return True
        else:
            return False

    def __le__(self, other):
        if self._absname <= other._absname:
            return True
        else:
            return False

    def __ne__(self, other):
        if self._absname != other._absname:
            return True
        else:
            return False

    def __gt__(self, other):
        if self._absname > other._absname:
            return True
        else:
            return False

    def __ge__(self, other):
        if self._absname >= other._absname:
            return True
        else:
            return False

    def __hash__(self):
        return hash(self._absname)

class ProcessOnDevice(object):
    """Class providing an abstraction for a process on the device"""
    correct_line = ('[^\\s:]+:[^\\s:]+:[^\\s:]+:[^\\s:]+\\s+[^\\s]+\\s+[0-9]+\\s+[0-9]+\\s+[^\\s]+.*')
    def __init__(self, line):
        if not re.match(ProcessOnDevice.correct_line, line):
            raise Exception('Bad process "{}"'.format(line))
        p = line.split(None, 4)
        self._context = Context(p[0])
        self._user = p[1]
        self._pid = p[2]
        self._ppid = p[3]
        self._name = p[4]

    @property
    def context(self):
        """Get the process context"""
        return self._context

    @property
    def user(self):
        """Get the process UNIX user"""
        return self._user

    @property
    def pid(self):
        """Get the process PID"""
        return self._pid

    @property
    def ppid(self):
        """Get the process PPID"""
        return self._ppid

    @property
    def name(self):
        """Get the process name"""
        return self._name

    def __repr__(self):
        return "{} {}".format(self._pid, self._name)

    def __eq__(self, other):
        if self._pid == other._pid:
            return True
        else:
            return False

    def __lt__(self, other):
        if int(self._pid) < int(other._pid):
            return True
        else:
            return False

    def __le__(self, other):
        if int(self._pid) <= int(other._pid):
            return True
        else:
            return False

    def __ne__(self, other):
        if self._pid != other._pid:
            return True
        else:
            return False

    def __gt__(self, other):
        if int(self._pid) > int(other._pid):
            return True
        else:
            return False

    def __ge__(self, other):
        if int(self._pid) >= int(other._pid):
            return True
        else:
            return False

    def __hash__(self):
        return int(self._pid)

def get_adb_call(root_adb, device, command):
    """Return a list representing the adb command to run the command string"""
    call = [adb, "-s", device, "shell"]
    if root_adb == "root_adb":
        # Root adb-specific things
        pass
    if root_adb == "root_shell":
        # Root shell-specific things
        call.extend(["su", "-c"])
    if root_adb == "not_root":
        # Non root-specific things
        pass
    call.extend(shlex.split(command))
    return call

def check_root_adb(device):
    """Check what level of root we can get on the device.
    This function cannot use get_adb_call, as that requires
    this function to be run first."""
    # Run adb as root
    root_status = check_output([adb, "-s", device, "root"]).strip('\r\n')
    if (root_status == "adbd is already running as root" or
            root_status == "restarting adbd as root"):
        # We have root
        return "root_adb"
    root_status = check_output(
            [adb, "-s", device, "shell", "su", "-c", "id"]).strip('\r\n')
    if "uid=0(root) gid=0(root)" in root_status:
        # We have a root shell
        return "root_shell"
    # We don't have root
    return "not_root"

def check_adb():
    """Start adb if not started already"""
    try:
        with open(os.devnull, "w") as devnull:
            check_call(["pgrep", "adb"], stdout=devnull)
    except CalledProcessError: # adb is not running
        try:
            check_call([adb, "devices"])
        except CalledProcessError:
            print 'Could not start adb.'
            return False
    return True

def get_devices():
    """Select one of the devices connected through adb"""
    # Split by newline and remove first line ("List of devices attached")
    devices = check_output([adb, "devices", "-l"]).split('\n')[1:]
    devices = [x for x in devices if x] # Remove empty strings
    return devices

def device_picker():
    """Select one of the devices"""
    devices = get_devices()
    if not devices:
        # No devices connected
        print "No devices connected."
        return None
    choice = 0
    if len(devices) > 1:
        # Ask user which device
        while True:
            print "Choose a device:"
            for i, x in enumerate(devices):
                #TODO might want to change the formatting of x
                print "[{}]\t{}".format(i, x)
            choice = raw_input("> ")
            if choice in [str(x) for x in range(len(devices))]:
                break
    return devices[int(choice)].split()[0]

def setup_policy(sepolicy, device):
    """Return a policy object, initialised from either a policy file or
    a connected Android device"""
    if sepolicy is None:
        if device is None:
            return None

        # Get policy from device
        tmp_dir = tempfile.mkdtemp()
        policy_file = "/sys/fs/selinux/policy"
        sepolicy = os.path.join(tmp_dir, "sepolicy")
        #TODO remove the directory once we're done with the policy
        try:
            check_call([adb, "-s", device, "pull", policy_file, sepolicy])
        except CalledProcessError:
            print "Failed to get the policy from the selected device"
            sys.exit(1)
        print 'Parsing policy "{}" from device...'.format(policy_file)
    else:
        print 'Parsing policy "{}"...'.format(sepolicy)

    p = Policy(sepolicy)
    return p

def polinfo(args):
    """Print policy information"""
    if args.policy is None:
        if not initialise_device(args):
            sys.exit(1)

    p = setup_policy(args.policy, args.device)
    if p is None:
        print "You need to provide either a policy or a running Android device"
        sys.exit(1)

    print "Device {} is running Android {} with SELinux in {} mode.".format(
            args.device, get_android_version(args.device),
            get_selinux_mode(args.device).lower())

    if args.info_domains:
        print "The policy contains {} domains:".format(len(p.domains))
        for d in p.domains:
            print d
    else:
        print "Classes:\t\t{}".format(len(p.classes))
        print "Types:\t\t\t{}".format(len(p.types))
        print "Attributes:\t\t{}".format(len(p.attrs))
        print "Domains:\t\t{}".format(len(p.domains))
        print "Initial SIDs:\t\t{}".format(len(p.isids))
        print "Capabilities:\t\t{}".format(len(p.polcaps))
        print "Roles:\t\t\t{}".format(len(p.roles))
        print "Users:\t\t\t{}".format(len(p.users))
        print "Fs_uses:\t\t{}".format(len(p.fs_uses))
        print "Genfscons:\t\t{}".format(len(p.genfscons))
        print "Portcons:\t\t{}".format(len(p.portcons))
        print "MLS sensitivities:\t{}".format(len(p.levels))
        print "MLS categories:\t\t{}".format(len(p.cats))
        print "MLS constraints:\t{}".format(len(p.constraints))

        print "Allow rules:\t\t{}".format(len(p.allow))
        print "Auditallow rules:\t{}".format(len(p.auditallow))
        print "Dontaudit rules:\t{}".format(len(p.dontaudit))
        print "Type_trans rules:\t{}".format(len(p.type_trans))
        print "Type_change rules:\t{}".format(len(p.type_change))
        print "Type_member rules:\t{}".format(len(p.type_member))
        print "Role_allow rules:\t{}".format(len(p.role_allow))
        print "Role_trans rules:\t{}".format(len(p.role_trans))
        print "Range_trans rules:\t{}".format(len(p.range_trans))

def get_android_version(device):
    """Get the Android version from a connected device"""
    return check_output(
            [adb, "-s", device, "shell", "getprop", "ro.build.version.release"]
            ).strip('\r\n')

def get_selinux_mode(device):
    """Get the SELinux mode from a connected device"""
    return check_output(
            [adb, "-s", device, "shell", "getenforce"]).strip('\r\n')

def get_processes(device):
    """Get the processes from a connected device"""
    if device is None:
        return None
    procs = {}
    # Split by newlines and remove first line ("LABEL USER PID PPID NAME")
    ps = check_output(
            [adb, "-s", device, "shell", "ps", "-Z"]).split('\r\n')[1:]
    for line in ps:
        if line:
            try:
                p = ProcessOnDevice(line)
            except Exception as e:
                print e
                continue
            procs[p.pid] = p
    return procs

def process_picker(args, procs):
    """Pick a process according to the command line arguments"""
    p = None
    # Match by PID
    if args.pid and args.pid in procs:
        p = procs[args.pid]
    # Match by exact name
    elif args.process:
        for i in procs.values():
            if i.name == args.process:
                p = i
                break
    # Match by partial name
    if p is None:
        for i in procs.values():
            if args.process in i.name:
                p = i
                break
    return p

def get_files(device, path='/', single_file=False):
    """Get the files under the given path from a connected device"""
    files_dict = {}
    path = os.path.normpath(path)
    if device is None:
        return None
    listing = check_output(
            [adb, "-s", device, "shell", "su", "-c", "ls", "-RZ", path]
            ).split('\r\n')
    # Parse ls -RZ output for a single file
    if single_file:
        try:
            f = FileOnDevice(listing[0], os.path.dirname(path))
        except Exception as e:
            print f
            print e
            return None
        files_dict[f.absname] = f
        return files_dict
    # Parse ls -RZ output for a path
    # For some reason, ls -RZ "<DIRECTORY>" output begins with a blank line.
    # This makes parsing easier
    new_dir = False
    firstrun = True
    for i in listing:
        if new_dir: # Initialise new directory
            d = i.strip(':')
            new_dir = False
            continue
        if not i: # If the current line is empty, request new directory
            new_dir = True
            firstrun = False
            continue
        try:
            f = FileOnDevice(i, d)
        except Exception as e:
            if firstrun:
                # If this is the very first line, the command failed outright
                print e
                return None
            print 'In directory "{}"'.format(d)
            print e
            continue
        files_dict[f.absname] = f
    return files_dict

def files(args):
    """List files from a device, with the option
    to filter by process that can access them"""
    if not initialise_device(args):
        sys.exit(1)

    args.root_adb = check_root_adb(args.device)
    if args.root_adb == "not_root":
        print "WARNING: Adb can not run as root on the device."
        print "Information shown by the tool will be incomplete."

    global files_on_device_no
    if not args.pid and not args.process: # Just list all the files
        files_dict = get_files(args.device)
        files_on_device_no = len(files_dict.keys())
        accessible_files, file_permissions = files_filter(None, None, files_dict)
        print_files(args, None, accessible_files, file_permissions)
    else:
        p = setup_policy(None, args.device)
        if p is None:
            print "You need to provide either a policy or a running Android device"
            sys.exit(1)

        processes_dict = get_processes(args.device)
        process = process_picker(args, processes_dict)
        if process is None:
            if args.pid:
                print "There is no process with PID {} running on the device.".format(args.pid)
            elif args.process:
                print 'There is no process "{}" running on the device'.format(args.process)
            sys.exit(1)

        print 'The "{}" process with PID {} is running in the "{}" context'.format(
                process.name, process.pid, process.context)
        files_dict = get_files(args.device)
        files_on_device_no = len(files_dict.keys())
        accessible_files, file_permissions = files_filter(p, process, files_dict)
        print_files(args, process, accessible_files, file_permissions)

def files_filter(policy, process, files_dict):
    """Filter files by a process that can access them"""
    accessible_files = defaultdict(list)
    if process is None:
        accessible_types = None
    else:
        accessible_types = policy.get_types_accessible_by(process.context)
    file_permissions = defaultdict(set)

    if accessible_types is None: # Just list all files
        for f in files_dict.values():
            accessible_files[f.context].append(f)
    else:
        for f in files_dict.values():
            #TODO expand matching to full context?
            if f.context.type in accessible_types:
                # We have some rule to this target type
                first_match = True
                for r in accessible_types[f.context.type]:
                    if f.security_class == r.security_class:
                        # We have some rule applicable to this file class
                        file_permissions[f].update(r.permissions)
                        if first_match:
                            accessible_files[f.context].append(f)
                            first_match = False
    return [accessible_files, file_permissions]

def print_files(args, process, accessible_files, file_permissions):
    """Print the filtered files"""
    extension = "txt"
    # Sanitize arguments
    device_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.device)
    if args.out:
        file_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', os.path.basename(args.out))
    if process is not None:
        process_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', process.name)

    i = 0 # File counter (files stored in nested dicts, count while processing)
    if args.out:
        if process is not None:
            output = "{}_files_{}_{}_{}_{}.{}".format(file_out, device_out,
                    process.pid, process.context, process_out, extension)
        else:
            output = "{}_files_{}.{}".format(file_out, device_out, extension)
        print 'Printing to "{}"...'.format(output)
        with open(output, "w") as thefile:
            for fc in accessible_files.values():
                i += len(fc)
                for f in fc:
                    out_line = f.absname
                    if args.context: # -Z or --context option
                        out_line = "{} {}".format(f.context, out_line)
                    # --permissions option requires a process
                    if args.permissions and process is not None:
                        out_line = "{}\t{} {{{}}}".format(out_line,
                                f.security_class, " ".join(sorted(file_permissions[f])))
                    print>>thefile, out_line
    else:
        for fc in accessible_files.values():
            i += len(fc)
            for f in fc:
                out_line = f.absname
                if args.context: # -Z or --context option
                    out_line = "{} {}".format(f.context, out_line)
                # --permissions option requires a process
                if args.permissions and process is not None:
                    out_line = "{}\t{} {{{}}}".format(out_line,
                            f.security_class, " ".join(sorted(file_permissions[f])))
                print out_line

    print "The device contains {} files.".format(files_on_device_no)
    if process is not None:
        print "The process has access to {} files.".format(i)

def initialise_device(args):
    """Initialise a device"""
    if not args.device: # Pick a device
        args.device = device_picker()
        if args.device is None:
            return False
    else: # Verify a user-provided device
        try:
            check_call([adb, "-s", args.device, "shell", "true"])
        except CalledProcessError:
            print 'Device "{}" does not exist.'.format(args.device)
            return False
    print "Using device {}".format(args.device)
    args.root_adb = check_root_adb(args.device)
    if args.root_adb == "not_root":
        print "WARNING: Adb can not run as root on the device."
        print "Information shown by the tool will be incomplete."
    return True

########################################
# Processes
def processes(args):
    """List processes on a device, with the option
    to filter by a file they can access"""
    if not initialise_device(args):
        sys.exit(1)

    processes_dict = get_processes(args.device)
    global processes_on_device_no
    processes_on_device_no = len(processes_dict.keys())
    if not args.file and not args.path: # Just list all the processes
        result = processes_filter(None, None, processes_dict)
        allowed_processes_by_file = result[0]
        process_permissions_by_file = result[1]
        print_processes(args, None, allowed_processes_by_file,
                process_permissions_by_file)
    else:
        p = setup_policy(None, args.device)
        if p is None:
            print "You need to provide either a policy or a running Android device"
            sys.exit(1)
        if args.file:
            files_dict = get_files(args.device, args.file, True)
            if files_dict is None:
                print 'File "{}" does not exist.'.format(args.file)
                sys.exit(1)
        else:
            files_dict = get_files(args.device, args.path)
            if files_dict is None:
                print 'Folder "{}" does not exist.'.format(args.path)
                sys.exit(1)
        result = processes_filter(p, files_dict, processes_dict)
        allowed_processes_by_file = result[0]
        process_permissions_by_file = result[1]
        print_processes(args, files_dict, allowed_processes_by_file,
                process_permissions_by_file)

def processes_filter(policy, files_dict, processes_dict):
    """Filter processes by one or more files they can access"""
    allowed_processes_by_file = defaultdict(list)
    if files_dict is None:
        allowed_domains_by_file = None
    else:
        allowed_domains_by_file = defaultdict()
        # Local variable not to query the policy for every file
        domains_by_target = defaultdict()
        for f in files_dict.values():
            if f.context.type not in domains_by_target.keys():
                domains_by_target[f.context.type] = policy.get_domains_allowed_to(f.context)
            allowed_domains_by_file[f] = domains_by_target[f.context.type]

    process_permissions_by_file = defaultdict(lambda: defaultdict(set))

    if allowed_domains_by_file is None: # No files, list all processes
        allowed_processes_by_file[None] = processes_dict
    else:
        for f in files_dict.values():
            for p in processes_dict.values():
                if p.context.type in allowed_domains_by_file[f]:
                    # We have some rule from this type
                    first_match = True
                    for r in allowed_domains_by_file[f][p.context.type]:
                        if f.security_class == r.security_class:
                            # We have some rule applicable to this file class
                            (process_permissions_by_file[f])[p].update(r.permissions)
                            if first_match:
                                allowed_processes_by_file[f].append(p)
                                first_match = False
    return [allowed_processes_by_file, process_permissions_by_file]

def print_processes(args, files_dict, allowed_processes_by_file,
        process_permissions_by_file):
    """Print filtered processes"""
    extension = "txt"
    # Sanitize arguments
    device_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.device)
    if args.out:
        file_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', os.path.basename(args.out))
    if args.file:
        filep_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.file)
    if args.path:
        path_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.path)

    if args.out:
        if files_dict is not None:
            if args.file:
                output = "{}_processes_{}_{}.{}".format(
                        file_out, device_out, filep_out, extension)
            else:
                output = "{}_processes_{}_{}.{}".format(
                        file_out, device_out, path_out, extension)
        else:
            output = "{}_processes_{}.{}".format(
                    file_out, device_out, extension)
        print 'Printing to "{}"...'.format(output)
        with open(output, "w") as thefile:
            if files_dict is None: # Just print all processes
                print>>thefile, 'There are {} processes running on the device:'.format(
                        processes_on_device_no)
                for p in allowed_processes_by_file[None].values():
                    # Setup output line
                    out_line = "\t{}\t{}".format(p.pid, p.name)
                    if args.context:
                        out_line = "\t{}{}".format(p.context, out_line)
                    print>>thefile, out_line
            else:
                print>>thefile, 'There are {} processes running on the device.'.format(
                        processes_on_device_no)
                for f, procs_list in allowed_processes_by_file.iteritems():
                    print>>thefile, 'The {} "{}" in the context "{}" can be accessed by {} processes:'.format(
                            f.security_class, f, f.context, len(procs_list))
                    for p in procs_list:
                        # Setup output line
                        out_line = "\t{}\t{}".format(p.pid, p.name)
                        if args.context:
                            out_line = "\t{}{}".format(p.context, out_line)
                        if args.permissions:
                            out_line = "{}\t{{{}}}".format(out_line,
                                    " ".join(sorted(process_permissions_by_file[f][p])))
                        print>>thefile, out_line
    else:
        if files_dict is None: # Just print all processes
            print 'There are {} processes running on the device:'.format(
                processes_on_device_no)
            for p in allowed_processes_by_file[None].values():
                # Setup output line
                out_line = "{}\t{}".format(p.pid, p.name)
                if args.context:
                    out_line = "{}\t{}".format(p.context, out_line)
                print out_line
        else:
            print 'There are {} processes running on the device.'.format(
                processes_on_device_no)
            for f, procs_list in allowed_processes_by_file.iteritems():
                print 'The {} "{}" in the context "{}" can be accessed by {} processes:'.format(
                        f.security_class, f, f.context, len(procs_list))
                for p in procs_list:
                    # Setup output line
                    out_line = "\t{}\t{}".format(p.pid, p.name)
                    if args.context:
                        out_line = "\t{}{}".format(p.context, out_line)
                    if args.permissions:
                        out_line = "{}\t{{{}}}".format(out_line,
                                " ".join(sorted(process_permissions_by_file[f][p])))
                    print out_line

def main():
    """The main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--adb',
            help="Path to your local root adb if not in your $PATH")
    parser.add_argument('--device',
            help="Specify a device to work with", metavar="<DEVICE>")
    subparsers = parser.add_subparsers(help='sub-command help')
    # Subparser for polinfo
    parser_polinfo = subparsers.add_parser('polinfo',
            help='Show policy info from device')
    parser_polinfo.add_argument('--policy',
            help="Show policy info from <FILE>", metavar="<FILE>")
    parser_polinfo.add_argument('--domains',
            help="Print the domains in the policy",
            action='store_true', dest="info_domains")
    parser_polinfo.set_defaults(func=polinfo)
    # Subparser for files
    parser_files = subparsers.add_parser('files',
            help='List all files on the device')
    parser_files.add_argument('-Z', "--context",
            action='store_true', help='print the context of each file')
    parser_files.add_argument('--process',
            help="List files that process named <PROCESS> can access",
            metavar="<PROCESS>")
    parser_files.add_argument('--pid',
            help="List files that process with PID <PID> can access",
            metavar="<PID>")
    parser_files.add_argument('--permissions',
            help='Print SELinux permissions for every file',
            action='store_true')
    parser_files.add_argument("-o", "--out",
            help="Write the file list to a file")
    parser_files.set_defaults(func=files)
    # Subparser for processes
    parser_processes = subparsers.add_parser('processes',
            help='List all processes on the device')
    parser_processes.add_argument('-Z', "--context", action='store_true',
            help='print the context of each process')
    parser_processes.add_argument('--file',
            help="List processes that can access file <FILE>",
            metavar="<FILE>")
    parser_processes.add_argument('--path',
            help="List processes that can access files under path <PATH>",
            metavar="<PATH>")
    parser_processes.add_argument('--permissions',
            help='Print SELinux permissions by each process on each file it has access to',
            action='store_true')
    parser_processes.add_argument("-o", "--out",
            help="Write the process list to a file")
    parser_processes.set_defaults(func=processes)

    args = parser.parse_args()
    global adb
    if args.adb:
        adb = args.adb

    if not check_adb():
        sys.exit(1)
    # Automatic callback from the argument parser
    # to the registered subcommand function
    args.func(args)

if __name__ == "__main__":
    main()
