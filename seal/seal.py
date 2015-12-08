#!/usr/bin/python2
#
# Written by Filippo Bonazzi
# Copyright (C) 2015 Aalto University
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

processes_on_device_no = 0
files_on_device_no = 0


class FileOnDevice(object):
    """Class providing an abstraction for a file on the device"""
    file_class_converter = {'-': 'file',      'file':      '-',  # File
                            'd': 'dir',       'dir':       'd',  # Directory
                            'c': 'chr_file',  'chr_file':  'c',  # Character device
                            'l': 'lnk_file',  'lnk_file':  'l',  # Symlink
                            'p': 'fifo_file', 'fifo_file': 'p',  # Named pipe
                            's': 'sock_file', 'sock_file': 's',  # Socket
                            'b': 'blk_file',  'blk_file':  'b'}  # Block device

    correct_line = (
        '[-dclpsb][-rwxst]{9}\\s+[^\\s]+\\s+[^\\s]+\\s+[^\\s:]+:[^\\s:]+:[^\\s:]+:[^\\s:]+\\s+.*')

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
    correct_line = (
        '[^\\s:]+:[^\\s:]+:[^\\s:]+:[^\\s:]+\\s+[^\\s]+\\s+[0-9]+\\s+[0-9]+\\s+[^\\s]+.*')

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


def get_adb_call(device, root_adb, command):
    """Return a list representing the adb command to run the command string"""
    # TODO: merge in appropriate Device-class methods
    call = [adb, "-s", device, "shell"]
    if root_adb == "root_adb":
        # Root adb-specific things
        pass
    elif root_adb == "root_shell":
        # Root shell-specific things
        call.extend(["su", "-c"])
    elif root_adb == "not_root":
        # Non root-specific things
        pass
    call.extend(shlex.split(command))
    return call


def device_picker(devices):
    """Select one of the devices"""
    if not devices:
        raise RuntimeError("No devices connected.")
    choice = 0
    if len(devices) > 1:
        # Ask user which device
        while True:
            print "Choose a device:"
            for i, x in enumerate(devices):
                # TODO might want to change the formatting of x
                print "[{}]\t{}".format(i, x)
            choice = raw_input("> ")
            if choice in [str(x) for x in range(len(devices))]:
                break
    return devices[int(choice)].split()[0]


def polinfo(args):
    """Print policy information"""
    # Begin initialisation
    # TODO: add logging
    p = None
    if not args.policy:
        # If we have no policy, use a device
        if not args.device:
            # Use the provided custom adb, if any
            if args.adb:
                devices = Device.get_devices(args.adb)
            else:
                devices = Device.get_devices()
            args.device = device_picker(devices)
        try:
            # Use the provided custom adb, if any
            if args.adb:
                device = Device(args.device, args.adb)
            else:
                device = Device(args.device)
        except ValueError as e:
            self.log.error(e)
            self.log.error("Could not create device, aborting...")
            raise RuntimeError
        p = Policy(device)
    else:
        # Use the provided policy
        p = Policy(None, args.policy)
    if not p:
        self.log.error("You need to provide either a valid policy "
                       "or a running Android device.")
        raise RuntimeError
    # End initialisation
    print "Device {} is running Android {} with SELinux in {} mode.".format(
        device, device.android_version, device.selinux_mode)

    if args.info_domains:
        print "The policy contains {} domains:".format(len(p.domains))
        for d in p.domains:
            print d
    else:
        # TODO: convert to use p.policy.<...> except for types, attrs, classes
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


def process_picker(args, processes):
    """Pick a process according to the command line arguments."""
    candidate = None
    # Match by PID
    if args.pid and args.pid in processes:
        candidate = processes[args.pid]
    # Match by exact name
    elif args.process:
        for proc in processes.values():
            if proc.name == args.process:
                candidate = proc
                break
    # If we haven't matched the PID or exact name, match the partial name
    if candidate is None:
        for proc in processes.values():
            if args.process in proc.name:
                candidate = proc
                break
    return candidate


def files(args):
    """List files from a device, with the option
    to filter by process that can access them"""
    # Start initialization
    # If we are not provided with a device, select one
    if not args.device:
        # Use the provided custom adb, if any
        if args.adb:
            devices = Device.get_devices(args.adb)
        else:
            devices = Device.get_devices()
        args.device = device_picker(devices)
    # Create the device
    try:
        # Use the provided custom adb, if any
        if args.adb:
            device = Device(args.device, args.adb)
        else:
            device = Device(args.device)
    except ValueError as e:
        self.log.error(e)
        self.log.error("Could not create device, aborting...")
        raise RuntimeError
    p = Policy(device)
    if not p:
        self.log.error("You need to provide either a valid policy "
                       "or a running Android device.")
        raise RuntimeError
    # End initialization

    global files_on_device_no
    if not args.pid and not args.process:
        # Just list all the files
        # TODO: refactor all these heavy functions
        files_dict = device.get_files()
        files_on_device_no = len(files_dict.keys())
        # TODO fix printing for unfiltered files
        print_files(args, None, files_dict, None)
    else:
        # Filter the files by process
        process = process_picker(args, device.get_processes())
        if process is None:
            if args.pid:
                self.log.error("There is no process with PID %s running "
                               "on the device.", args.pid)
            elif args.process:
                self.log.error("There is no process \"%s\" running "
                               "on the device", args.process)
            raise RuntimeError
        self.log.info("The \"%s\" process with PID %s is running in the \"%s\""
                      " context", process.name, process.pid, process.context)
        # TODO: refactor all these heavy functions
        files_dict = device.get_files()
        # TODO: MARK
        files_on_device_no = len(files_dict.keys())
        file_permissions = get_process_permissions(p, process, files_dict)
        print_files(args, process, files_dict, file_permissions)


def get_process_permissions(policy, process, files_dict):
    """Get the permissions a given process has on the given files.

    Returns a dictionary (filename, set(perms))."""
    file_permissions = {}
    accessible_types = policy.get_types_accessible_by(process.context)
    for fname, f in files_dict.iteritems():
        # TODO: expand matching to full context?
        if f.context.type in accessible_types:
            # We have some rule to this target type
            first_match = True
            for rule in accessible_types[f.context.type]:
                if f.security_class == rule.tclass:
                    # We have some rule applicable to this file class
                    if fname in file_permissions:
                        file_permissions[fname].update(rule.perms)
                    else:
                        file_permissions[fname] = rule.perms
    return file_permissions


def print_files(args, process, files_dict, file_permissions):
    """Print a list of files.
    If a process and file_permissions dictionary is supplied, also print
    the permissions the process has on each file."""
    extension = "txt"
    # Sanitize arguments
    device_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.device)
    if args.out:
        file_out = os.path.abspath(args.out)
    if process:
        process_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', process.name)

    # Print to file
    if args.out:
        if process:
            output = "{0}_files_{1}_{2.pid}_{2.context}_{3}.{4}".format(
                file_out, device_out, process, process_out, extension)
        else:
            output = "{}_files_{}.{}".format(file_out, device_out, extension)
        self.log.info("Printing to \"%s\"...", output)
        with open(output, "w") as thefile:
            if process and file_permissions:
                # Print only the files a process has permissions to
                for fname, f in files_dict.iteritems():
                    if fname in file_permissions:
                        out_line = fname
                        # -Z or --context option
                        if args.context:
                            out_line = f.context + " " + out_line
                        # --permissions option
                        if args.permissions:
                            out_line += "\t" + f.security_class + " {"
                            out_line += " ".join(
                                sorted(file_permissions[fname])) + "}"
                        print>>thefile, out_line
            else:
                # Print all files
                for fname, f in files_dict.iteritems():
                    out_line = fname
                    # -Z or --context option
                    if args.context:
                        out_line = f.context + " " + out_line
                    print>>thefile, out_line
    # Print to stdout
    else:
        # TODO: MARK.1
        for fc in accessible_files.values():
            i += len(fc)
            for f in fc:
                out_line = f.absname
                if args.context:  # -Z or --context option
                    out_line = "{} {}".format(f.context, out_line)
                # --permissions option requires a process
                if args.permissions and process is not None:
                    out_line = "{}\t{} {{{}}}".format(out_line,
                                                      f.security_class, " ".join(sorted(file_permissions[f])))
                print out_line

    print "The device contains {} files.".format(files_on_device_no)
    if process is not None:
        print "The process has access to {} files.".format(i)


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
    if not args.file and not args.path:  # Just list all the processes
        result = processes_filter(None, None, processes_dict)
        allowed_processes_by_file = result[0]
        process_permissions_by_file = result[1]
        print_processes(args, None, allowed_processes_by_file,
                        process_permissions_by_file)
    else:
        p = Policy(args.device)
        if p is None:
            print "You need to provide either a policy or a running Android device"
            sys.exit(1)
        if args.file:
            files_dict = get_files(args.device, args.root_adb, args.file, True)
            if files_dict is None:
                print 'File "{}" does not exist.'.format(args.file)
                sys.exit(1)
        else:
            files_dict = get_files(args.device, args.root_adb, args.path)
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
                domains_by_target[
                    f.context.type] = policy.get_domains_allowed_to(f.context)
            allowed_domains_by_file[f] = domains_by_target[f.context.type]

    process_permissions_by_file = defaultdict(lambda: defaultdict(set))

    if allowed_domains_by_file is None:  # No files, list all processes
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
                            (process_permissions_by_file[f])[
                                p].update(r.permissions)
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
        file_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-',
                          os.path.basename(args.out))
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
            if files_dict is None:  # Just print all processes
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
        if files_dict is None:  # Just print all processes
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

    # Automatic callback from the argument parser
    # to the registered subcommand function
    args.func(args)

if __name__ == "__main__":
    main()
