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

"""The SELinux Analytics Library command line frontend."""

import argparse
import readline  # pylint: disable=unused-import
import os
import sys
import re
import logging
from sealib.policy import Policy
import sealib.device


def device_picker(devices):
    """Select one of the devices"""
    if not devices:
        raise RuntimeError("No devices connected.")
    if len(devices) == 1:
        return devices.keys()[0]
    if len(devices) > 1:
        # Ask user which device
        devs = {}
        for i, name in enumerate(devices):
            devs[int(i)] = name
        while True:
            # Print dialog and list of devices
            print "Choose a device:"
            for i, name in devs.iteritems():
                print "[{}]\t{}".format(i, name)
            # Get the input
            choice = raw_input("> ")
            # Check input range
            if int(choice) in devs:
                # If valid, return
                return devs[int(choice)]


def polinfo(args):
    """Print policy information"""
    # Setup logging
    if args.verbosity == 4:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbosity == 3:
        logging.basicConfig(level=logging.INFO)
    elif args.verbosity == 2:
        logging.basicConfig(level=logging.WARNING)
    elif args.verbosity == 1:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbosity == 0:
        logging.basicConfig(level=logging.CRITICAL)
    # Begin initialisation
    try:
        if not args.policy:
            # If we have no policy, use a device
            device = get_device(args.device, args.adb)
            # Workaround, make sure we propagate the device name
            if not args.device:
                args.device = device.name
            p = Policy(device)
        else:
            # Use the provided policy
            p = Policy(None, args.policy)
    except (ValueError, RuntimeError):
        logging.critical("You need to provide either a valid policy "
                         "or a running Android device.")
        sys.exit(1)
    # End initialisation

    if not args.policy:
        print "Device {} is running Android {} with SELinux in {} mode.".format(
            device, device.android_version, device.selinux_mode)

    if args.info_domains:
        print "The policy contains {} domains:".format(p.domains_count)
        for dom in p.domains.keys():
            print dom
    else:
        print "Classes:\t\t{}".format(p.classes_count)
        print "Types:\t\t\t{}".format(p.types_count)
        print "Attributes:\t\t{}".format(p.attrs_count)
        print "Domains:\t\t{}".format(p.domains_count)
        print "Initial SIDs:\t\t{}".format(p.policy.initialsids_count)
        print "Capabilities:\t\t{}".format(p.policy.polcap_count)
        print "Roles:\t\t\t{}".format(p.policy.role_count)
        print "Users:\t\t\t{}".format(p.policy.user_count)
        print "Fs_uses:\t\t{}".format(p.policy.fs_use_count)
        print "Genfscons:\t\t{}".format(p.policy.genfscon_count)
        print "Portcons:\t\t{}".format(p.policy.portcon_count)
        print "MLS sensitivities:\t{}".format(p.policy.level_count)
        print "MLS categories:\t\t{}".format(p.policy.category_count)
        print "MLS constraints:\t{}".format(p.policy.constraint_count)
        print "Permissive types:\t{}".format(p.policy.permissives_count)

        print "Allow rules:\t\t{}".format(p.policy.allow_count)
        print "Auditallow rules:\t{}".format(p.policy.auditallow_count)
        print "Dontaudit rules:\t{}".format(p.policy.dontaudit_count)
        print "Type_trans rules:\t{}".format(p.policy.type_transition_count)
        print "Type_change rules:\t{}".format(p.policy.type_change_count)
        print "Type_member rules:\t{}".format(p.policy.type_member_count)
        print "Role_allow rules:\t{}".format(p.policy.role_allow_count)
        print "Role_trans rules:\t{}".format(p.policy.role_transition_count)
        print "Range_trans rules:\t{}".format(p.policy.range_transition_count)


def process_picker(args, proclist):
    """Pick a process according to the command line arguments."""
    candidate = None
    # Match by PID
    if args.pid and args.pid in proclist:
        candidate = proclist[args.pid]
    # Match by exact name
    elif args.process:
        for proc in proclist.values():
            if proc.name == args.process:
                candidate = proc
                break
    # If we haven't matched the PID or exact name, match the partial name
    if candidate is None:
        for proc in proclist.values():
            if args.process in proc.name:
                candidate = proc
                break
    return candidate


def get_device(name, adb):
    """Select a device name from the connected devices and return the
    corresponding Device object."""
    # Select a device name from the connected devices, if not already provided
    # Use the provided custom adb, if any
    if adb:
        devices = sealib.device.Device.get_devices(adb)
    else:
        devices = sealib.device.Device.get_devices()
    if not name:
        # Raises RuntimeError if no devices connected
        name = device_picker(devices)
    else:
        if name not in devices:
            logging.critical("Invalid device: \"%s\"", name)
            raise ValueError
    # Create the device
    try:
        # Use the provided custom adb, if any
        if adb:
            device = sealib.device.Device(name, adb)
        else:
            device = sealib.device.Device(name)
    except ValueError as e:
        logging.critical(e)
        logging.critical("Could not create device, aborting...")
        raise RuntimeError
    return device


def files(args):
    """List files from a device, with the option to filter them by a
    process that can access them."""
    # Setup logging
    if args.verbosity == 4:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbosity == 3:
        logging.basicConfig(level=logging.INFO)
    elif args.verbosity == 2:
        logging.basicConfig(level=logging.WARNING)
    elif args.verbosity == 1:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbosity == 0:
        logging.basicConfig(level=logging.CRITICAL)
    # Start initialization
    # Create the device
    try:
        device = get_device(args.device, args.adb)
    except (RuntimeError, ValueError):
        sys.exit(1)
    # Workaround, make sure we propagate the device name
    if not args.device:
        args.device = device.name
    # End initialization

    if not args.pid and not args.process:
        # Just list all the files
        files_dict = device.get_files()
        print_files(args, None, files_dict, None)
    else:
        # Create the policy
        try:
            p = Policy(device)
        except (ValueError, RuntimeError):
            logging.critical("You need to provide a running Android device.")
            sys.exit(1)
        # Filter the files by process
        process = process_picker(args, device.get_processes())
        if process is None:
            if args.pid:
                logging.critical("There is no process with PID %s running "
                                 "on the device.", args.pid)
            elif args.process:
                logging.critical("There is no process \"%s\" running "
                                 "on the device", args.process)
            sys.exit(1)
        logging.info("The \"%s\" process with PID %s is running in the "
                     "\"%s\" context", process.name, process.pid,
                     process.context)
        files_dict = device.get_files()
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
        # If we are filtering by a process, name the output file accordingly
        if process:
            output = "{0}_files_{1}_{2.pid}_{2.context}_{3}.{4}".format(
                file_out, device_out, process, process_out, extension)
        # We are not filtering by a process, name the output file accordingly
        else:
            output = "{}_files_{}.{}".format(file_out, device_out, extension)
        logging.info("Printing to \"%s\"...", output)
        # Open file for printing
        with open(output, "w") as thefile:
            if process and file_permissions:
                # Print only the files a process has permissions to
                for fname, f in files_dict.iteritems():
                    if fname in file_permissions:
                        out_line = fname
                        # -Z or --context option
                        if args.context:
                            out_line = str(f.context) + " " + out_line
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
                        out_line = str(f.context) + " " + out_line
                    print>>thefile, out_line
    # Print to stdout
    else:
        if process and file_permissions:
            # Print only the files a process has permissions to
            for fname, f in files_dict.iteritems():
                if fname in file_permissions:
                    out_line = fname
                    # -Z or --context option
                    if args.context:
                        out_line = str(f.context) + " " + out_line
                    # --permissions option
                    if args.permissions:
                        out_line += "\t" + f.security_class + " {"
                        out_line += " ".join(
                            sorted(file_permissions[fname])) + "}"
                    print out_line
        else:
            # Print all files
            for fname, f in files_dict.iteritems():
                out_line = fname
                # -Z or --context option
                if args.context:
                    out_line = str(f.context) + " " + out_line
                print out_line

    print "The device contains {} files.".format(len(files_dict))
    if process and file_permissions:
        print "The process has access to {} files.".format(
            len(file_permissions))


########################################
# Processes
def processes(args):
    """List processes on a device, with the option to filter them by a file
    they can access."""
    # Setup logging
    if args.verbosity == 4:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbosity == 3:
        logging.basicConfig(level=logging.INFO)
    elif args.verbosity == 2:
        logging.basicConfig(level=logging.WARNING)
    elif args.verbosity == 1:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbosity == 0:
        logging.basicConfig(level=logging.CRITICAL)
    # Start initialization
    # Create the device
    try:
        device = get_device(args.device, args.adb)
    except (ValueError, RuntimeError):
        sys.exit(1)
    # Workaround, make sure we propagate the device name
    if not args.device:
        args.device = device.name
    # End initialization

    processes_dict = device.get_processes()
    if not args.file and not args.path:
        # Just list all the processes
        print_processes(args, None, processes_dict, None)
    else:
        # Create the policy
        try:
            p = Policy(device)
        except (ValueError, RuntimeError):
            logging.critical("You need to provide a running Android device.")
            sys.exit(1)
        # Filter the processes by file
        if args.file:
            files_dict = device.get_file(args.file)
            if files_dict is None:
                logging.critical(
                    "There is no file \"%s\" on the device.", args.file)
                sys.exit(1)
        else:
            files_dict = device.get_files(args.path)
            if files_dict is None:
                logging.critical(
                    "There is no folder \"%s\" on the device.", args.file)
                sys.exit(1)
        proc_permissions = get_file_permissions(p, files_dict,
                                                processes_dict)
        print_processes(args, files_dict, processes_dict, proc_permissions)


def get_file_permissions(policy, files_dict, processes_dict):
    """Get the processes that can access a set of files, with their related
    permissions.

    Returns a nested dictionary {file: {process: set(perms)}}."""
    # Local variable not to query the policy for every file
    hugemap = {}
    # Prepare a nested dictionary [type][class]{domain: list(rules)}
    # This contains all allow rules "allow domain type: class {...}"
    # accessible by the three indexes [type], [class], [domain]
    for f in files_dict.values():
        if f.context.type not in hugemap:
            # We don't know this type
            hugemap[f.context.type] = {}
        if f.security_class not in hugemap[f.context.type]:
            # We don't know this [type][class] combination
            dmns = policy.get_domains_allowed_to(f.context, f.security_class)
            hugemap[f.context.type][f.security_class] = dmns
    # Prepare the output dictionary
    # This will be accessed as outmap[fname][pname], giving the set of
    # permissions associated to each pair of values of the indexes
    outmap = {}
    # Process all files
    for fname, f in files_dict.iteritems():
        if fname not in outmap:
            outmap[fname] = {}
        for pname, p in processes_dict.iteritems():
            if p.context.type in hugemap[f.context.type][f.security_class]:
                # We have some rule from this type to the current file
                if pname not in outmap[fname]:
                    # If we don't have any permissions for this process yet
                    outmap[fname][pname] = set()
                for rule in hugemap[f.context.type][f.security_class][p.context.type]:
                    outmap[fname][pname].update(rule.perms)
    return outmap


def print_processes(args, files_dict, processes_dict, proc_permissions):
    """Print a list of processes.
    If a files_dict and proc_permissions dictionary is supplied, also print
    the permissions each process has on each file."""
    extension = "txt"
    # Sanitize arguments
    device_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.device)
    if args.out:
        file_out = os.path.basename(args.out)
    if args.file:
        filep_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.file)
    if args.path:
        path_out = re.sub(r'[^a-zA-Z-_0-9.:]', r'-', args.path)

    # Print to file
    if args.out:
        # If we are filtering by a file or path, name the output file
        if files_dict and proc_permissions:
            # If we are filtering by a file
            if args.file:
                output = "{}_processes_{}_{}.{}".format(
                    file_out, device_out, filep_out, extension)
            # If not, we are filtering by a path
            else:
                output = "{}_processes_{}_{}.{}".format(
                    file_out, device_out, path_out, extension)
        # We are not filtering by a file or path, name the output file
        else:
            output = "{}_processes_{}.{}".format(
                file_out, device_out, extension)
        logging.info("Printing to \"%s\"...", output)
        # Open the file for printing
        with open(output, "w") as thefile:
            if files_dict and proc_permissions:
                # Print only the processes that have permissions on the file(s)
                tmp = "There are {} processes running on the device."
                print>>thefile, tmp.format(len(processes_dict))
                # For each file some process has permissions to
                for fname, procperm_dict in proc_permissions.iteritems():
                    # Get the corresponding FileOnDevice object
                    f = files_dict[fname]
                    tmp = "The {} \"{}\" in the context \"{}\" can be " \
                        "accessed by {} processes:"
                    print>>thefile, tmp.format(f.security_class, fname,
                                               f.context, len(procperm_dict))
                    # For each process that has permissions over the cur file
                    for pid, perms in procperm_dict.iteritems():
                        # Get the corresponding ProcessOnDevice object
                        p = processes_dict[pid]
                        # Setup output line
                        out_line = "\t{}\t{}".format(pid, p.name)
                        # -Z or --context option
                        if args.context:
                            out_line = "\t" + str(p.context) + out_line
                        # --permissions option
                        if args.permissions:
                            out_line += "\t{" + " ".join(sorted(perms)) + "}"
                        print>>thefile, out_line
            else:
                # Just print all processes
                tmp = "There are {} processes running on the device:"
                print>>thefile, tmp.format(len(processes_dict))
                # For each process
                for pid, p in processes_dict.iteritems():
                    # Setup output line
                    out_line = "\t{}\t{}".format(pid, p.name)
                    # -Z or --context option
                    if args.context:
                        out_line = "\t" + str(p.context) + out_line
                    print>>thefile, out_line
    else:
        if files_dict and proc_permissions:
            # Print only the processes that have permissions on the file(s)
            tmp = "There are {} processes running on the device."
            print tmp.format(len(processes_dict))
            # For each file some process has permissions to
            for fname, procperm_dict in proc_permissions.iteritems():
                # Get the corresponding FileOnDevice object
                f = files_dict[fname]
                tmp = "The {} \"{}\" in the context \"{}\" can be " \
                    "accessed by {} processes:"
                print tmp.format(f.security_class, fname,
                                 f.context, len(procperm_dict))
                # For each process that has permissions over the cur file
                for pid, perms in procperm_dict.iteritems():
                    # Get the corresponding ProcessOnDevice object
                    p = processes_dict[pid]
                    # Setup output line
                    out_line = "\t{}\t{}".format(pid, p.name)
                    # -Z or --context option
                    if args.context:
                        out_line = "\t" + str(p.context) + out_line
                    # --permissions option
                    if args.permissions:
                        out_line += "\t{" + " ".join(sorted(perms)) + "}"
                    print out_line
        else:
            # Just print all processes
            tmp = "There are {} processes running on the device:"
            print tmp.format(len(processes_dict))
            # For each process
            for pid, p in processes_dict.iteritems():
                # Setup output line
                out_line = "\t{}\t{}".format(pid, p.name)
                # -Z or --context option
                if args.context:
                    out_line = "\t" + str(p.context) + out_line
                print out_line


def main():
    """The main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--adb', metavar="<ADB>",
                        help="Path to your local root adb if not in your $PATH")
    parser.add_argument("-s", "--device", metavar="<DEVICE>",
                        help="Specify a device to work with")
    subparsers = parser.add_subparsers(help='sub-command help')
    # Subparser for polinfo
    parser_polinfo = subparsers.add_parser('polinfo',
                                           help='Show policy info from device')
    parser_polinfo.add_argument('--policy', metavar="<FILE>",
                                help="Show policy info from <FILE>")
    parser_polinfo.add_argument('--domains',
                                help="Print the domains in the policy",
                                action='store_true', dest="info_domains")
    parser_polinfo.add_argument("-v", "--verbosity", metavar="<LVL>",
                                choices=[0, 1, 2, 3, 4], type=int, default=0,
                                help="Be verbose. Supported levels are 0-4, "
                                "with 0 being the default.")
    parser_polinfo.set_defaults(func=polinfo)
    # Subparser for files
    parser_files = subparsers.add_parser('files',
                                         help='List all files on the device')
    parser_files.add_argument('-Z', "--context", action='store_true',
                              help='print the context of each file')
    parser_files.add_argument('--process',
                              help="List files that process named <PROCESS> can access.",
                              metavar="<PROCESS>")
    parser_files.add_argument('--pid',
                              help="List files that process with PID <PID> can access.",
                              metavar="<PID>")
    parser_files.add_argument('--permissions',
                              help='Print SELinux permissions for every file',
                              action='store_true')
    parser_files.add_argument("-o", "--out", metavar="<OUT>",
                              help="Write the file list to a file")
    parser_files.add_argument("-v", "--verbosity", metavar="<LVL>",
                              choices=[0, 1, 2, 3, 4], type=int, default=0,
                              help="Be verbose. Supported levels are 0-4, "
                              "with 0 being the default.")
    parser_files.set_defaults(func=files)
    # Subparser for processes
    parser_processes = subparsers.add_parser('processes',
                                             help='List all processes on the device.')
    parser_processes.add_argument('-Z', "--context", action='store_true',
                                  help='print the context of each process.')
    parser_processes.add_argument('--file',
                                  help="List processes that can access file <FILE>.",
                                  metavar="<FILE>")
    parser_processes.add_argument('--path',
                                  help="List processes that can access files under path <PATH>.",
                                  metavar="<PATH>")
    parser_processes.add_argument('--permissions', action='store_true',
                                  help='Print SELinux permissions by each process'
                                  'on each file it has access to.')
    parser_processes.add_argument("-o", "--out", metavar="<OUT>",
                                  help="Write the process list to a file")
    parser_processes.add_argument("-v", "--verbosity", metavar="<LVL>",
                                  choices=[0, 1, 2, 3, 4], type=int, default=0,
                                  help="Be verbose. Supported levels are 0-4, "
                                  "with 0 being the default.")
    parser_processes.set_defaults(func=processes)

    args = parser.parse_args()

    # Automatic callback from the argument parser
    # to the registered subcommand function
    args.func(args)

if __name__ == "__main__":
    main()
