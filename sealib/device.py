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
"""TODO: file docstring"""

import subprocess
import logging
import os
import re
from sealib.policy import Context


class Device(object):
    """Class providing an abstraction for a connected Android device."""
    DEFAULT_POLICY_FILE = "/sys/fs/selinux/policy"
    DEFAULT_ADB = "adb"

    @staticmethod
    def get_devices(adb=DEFAULT_ADB):
        """Get the list of devices connected over adb."""
        # Check that adb is running
        Device.__start_adb(adb)
        # Split by newline and remove first line ("List of devices attached")
        # TODO: surround with try/except?
        devices = subprocess.check_output(
            [adb, "devices", "-l"]).split('\n')[1:]
        return [x for x in devices if x]  # Remove empty strings

    @staticmethod
    def __check_root_adb(device, adb):
        """Check what level of root we can get on the device."""
        cmd = [adb, "-s", device]
        # Initially assume we are not root
        root_adb = "not_root"
        # Check for increasingly high privilege levels
        # Check wether 'su' exists
        root_status = subprocess.check_output(
            cmd + ["shell", "command", "-v", "su"]).strip('\r\n')
        # If su exists, check if we can be root
        if root_status:
            root_status = subprocess.check_output(
                cmd + ["shell", "su", "-c", "id"]).strip('\r\n')
            if "uid=0(root) gid=0(root)" in root_status:
                # We have a root shell
                root_adb = "root_shell"
        # Try running adb as root
        root_status = subprocess.check_output(cmd + ["root"]).strip('\r\n')
        if (root_status == "adbd is already running as root" or
                root_status == "restarting adbd as root"):
            # We have root
            root_adb = "root_adb"
        # Return our level of root
        return root_adb

    @staticmethod
    def __start_adb(adb):
        """Start adb if not started already"""
        try:
            with open(os.devnull, "w") as dnl:
                subprocess.check_call(["pgrep", "'" + adb + "'"], stdout=dnl)
        except subprocess.CalledProcessError:
            # adb is not running
            try:
                # Try to start adb by calling "adb devices"
                with open(os.devnull, "w") as dnl:
                    subprocess.check_call([adb, "devices"], stdout=dnl)
            except subprocess.CalledProcessError:
                raise RuntimeError("Could not start adb (\"{}\").".format(adb))

    def __init__(self, name, adb=DEFAULT_ADB):
        """Initialise a device"""
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        if not name or not adb:
            raise ValueError("Bad device name or adb value.")
        # Verify the device name
        try:
            subprocess.check_call([adb, "-s", name, "shell", "true"])
        except subprocess.CalledProcessError:
            raise ValueError("Bad device name or adb value.")
        self.name = name
        self.adb = adb
        self.command = [self.adb, "-s", self.name]
        self.root_adb = Device.__check_root_adb(name, adb)
        if self.root_adb == "not_root":
            self.log.warning("Adb can not run as root on device \"%s\".", name)
            self.log.warning(
                "Information shown by the tool will be incomplete.")
        self.shell = self.__get_adb_shell()
        self._selinux_mode = None
        self._android_version = None

    def pull_file(self, source, target):
        """Copy a file from the source path on the device to the target path
        on the local machine."""
        if not source or not target:
            raise ValueError
        try:
            subprocess.check_call(self.command + ["pull", source, target])
        except subprocess.CalledProcessError as e:
            self.log.warning(e.msg)
            self.log.warning("Failed to copy \"%s:%s\" to %s",
                             self.name, source, target)
            raise ValueError
        else:
            self.log.debug("Copied \"%s:%s\" to \"%s\"",
                           self.name, source, target)

    def pull_policy(self, target, policy=DEFAULT_POLICY_FILE):
        """Copy the SELinux policy from the device to the target path.

        If no policy is specified, the default location is assumed."""
        self.pull_file(policy, target)

    def __str__(self):
        return self.name

    def __get_adb_shell(self):
        """Return the appropriate "adb shell" command for the current device,
        taking into account the type of root available.

        Returns the command as a list."""
        shell = self.command + ["shell"]
        if self.root_adb == "root_adb":
            # Root adb-specific things
            pass
        elif self.root_adb == "root_shell":
            # Root shell-specific things
            shell.extend(["su", "-c"])
        elif self.root_adb == "not_root":
            # Non root-specific things
            pass
        return shell

    @property
    def android_version(self):
        """The device Android version."""
        if not self._android_version:
            # Get the Android version from the connected device
            cmd = ["getprop", "ro.build.version.release"]
            # TODO: surround with try/except?
            tmp = subprocess.check_output(self.shell + cmd)
            self._android_version = tmp.strip('\r\n')
        return self._android_version

    @property
    def selinux_mode(self):
        """The device SELinux mode (enforcing/permissive)."""
        if not self._selinux_mode:
            # Get the SELinux mode from the connected device
            cmd = ["getenforce"]
            # TODO: surround with try/except?
            tmp = subprocess.check_output(self.shell + cmd)
            self._selinux_mode = tmp.strip('\r\n').lower()
        return self._selinux_mode

    def get_processes(self):
        """Get the processes running on the device.

        Returns a dictionary (PID, Process)."""
        processes = {}
        # Get ps output
        cmd = ["ps", "-Z"]
        # Split by newlines and remove first line ("LABEL USER PID PPID NAME")
        # TODO: surround with try/except?
        psz = subprocess.check_output(self.shell + cmd).split('\r\n')[1:]
        for line in psz:
            if line:
                try:
                    p = Process(line)
                except ValueError as e:
                    self.log.warning(e)
                else:
                    processes[p.pid] = p
        return processes

    def get_files(self, path="/"):
        """Get the files under the given path from a connected device.
        The path must be a directory.

        Returns a dictionary (filename, File)."""
        files_dict = {}
        path = os.path.normpath(path)
        cmd = ["ls", "-RZ", "'" + path + "'"]
        listing = subprocess.check_output(self.shell + cmd).split('\r\n')
        # Parse ls -RZ output for a directory
        # For some reason, the output of ls -RZ "<DIRECTORY>" begins
        # with a blank line. This makes parsing easier
        new_dir = False
        first_run = True
        for line in listing:
            # Initialise new directory
            if new_dir:
                directory = line.strip(':')
                new_dir = False
                continue
            # If the current line is empty, expect a new directory in the next
            if not line:
                new_dir = True
                first_run = False
                continue
            # Regular line describing a file
            try:
                f = File(line, directory)
            except ValueError as e:
                if first_run:
                    # If this is the very first line of the output, the
                    # command failed outright
                    self.log.error(e)
                    return None
                self.log.error("In directory \"%s\"", directory)
                self.log.error(e)
            else:
                files_dict[f.absname] = f
        return files_dict

    def get_file(self, path):
        """Get the file matching the given path from a connected device.
        The path must be a file.

        Returns a dictionary (filename, File)."""
        path = os.path.normpath(path)
        cmd = ["ls", "-RZ", "'" + path + "'"]
        listing = subprocess.check_output(self.shell + cmd).split('\r\n')
        # Parse ls -RZ output for a single file
        try:
            f = File(listing[0], os.path.dirname(path))
        except ValueError as e:
            self.log.error(e)
            return None
        else:
            return {f.absname: f}


class File(object):
    """Class providing an abstraction for a file on the device."""
    file_class_converter = {
        # pylint: disable=C0326
        '-': 'file',      'file':      '-',  # File
        'd': 'dir',       'dir':       'd',  # Directory
        'c': 'chr_file',  'chr_file':  'c',  # Character device
        'l': 'lnk_file',  'lnk_file':  'l',  # Symlink
        'p': 'fifo_file', 'fifo_file': 'p',  # Named pipe
        's': 'sock_file', 'sock_file': 's',  # Socket
        'b': 'blk_file',  'blk_file':  'b'}  # Block device

    # TODO: re.compile?
    correct_line = (
        r'[-dclpsb][-rwxst]{9}\s+(?:[^\s]+\s+){2}(?:[^\s:]+:){3,}[^\s:]+\s+.*')

    def __init__(self, l, d):
        if not re.match(File.correct_line, l):
            raise ValueError('Bad file "{}"'.format(l))
        line = l.split(None, 4)
        self._security_class = File.file_class_converter[l[0]]
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
        if self.absname == other.absname:
            return True
        else:
            return False

    def __lt__(self, other):
        if self.absname < other.absname:
            return True
        else:
            return False

    def __le__(self, other):
        if self.absname <= other.absname:
            return True
        else:
            return False

    def __ne__(self, other):
        if self.absname != other.absname:
            return True
        else:
            return False

    def __gt__(self, other):
        if self.absname > other.absname:
            return True
        else:
            return False

    def __ge__(self, other):
        if self.absname >= other.absname:
            return True
        else:
            return False

    def __hash__(self):
        return hash(self.absname)


class Process(object):
    """Class providing an abstraction for a process on the device"""
    # TODO: re.compile?
    correct_line = (
        r'(?:[^\s:]+:){3,}[^\s:]+\s+[^\s]+\s+[0-9]+\s+[0-9]+\s+[^\s]+.*')

    def __init__(self, line):
        if not re.match(Process.correct_line, line):
            raise ValueError('Bad process "{}"'.format(line))
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
        return "{} {}".format(self.pid, self.name)

    def __eq__(self, other):
        if self.pid == other.pid:
            return True
        else:
            return False

    def __lt__(self, other):
        if int(self.pid) < int(other.pid):
            return True
        else:
            return False

    def __le__(self, other):
        if int(self.pid) <= int(other.pid):
            return True
        else:
            return False

    def __ne__(self, other):
        if self.pid != other.pid:
            return True
        else:
            return False

    def __gt__(self, other):
        if int(self.pid) > int(other.pid):
            return True
        else:
            return False

    def __ge__(self, other):
        if int(self.pid) >= int(other.pid):
            return True
        else:
            return False

    def __hash__(self):
        return int(self.pid)
