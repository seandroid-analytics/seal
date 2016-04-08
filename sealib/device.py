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
"""Utility module to handle an Android device."""

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
        """Get the devices connected over adb.

        Returns a dictionary {name: full_adb_line}."""
        # Check that adb is running
        Device.__start_adb(adb)
        # Split by newline and remove first line ("List of devices attached")
        # TODO: surround with try/except?
        devices = subprocess.check_output(
            [adb, "devices", "-l"]).split('\n')[1:]
        tmp = {}
        for dev in devices:
            if dev:
                tmp[dev.split()[0]] = dev
        return tmp

    @staticmethod
    def __check_root_adb(device, adb):
        """Check what level of root we can get on the device."""
        cmd = [adb, "-s", device]
        # Initially assume we are not root
        root_adb = "not_root"
        # Try running adb as root
        root_status = subprocess.check_output(cmd + ["root"]).strip('\r\n')
        if (root_status == "adbd is already running as root" or
                root_status == "restarting adbd as root"):
            # We have root
            root_adb = "root_adb"
        else:
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
        # Return our level of root
        return root_adb

    @staticmethod
    def __start_adb(adb):
        """Start adb if not started already"""
        try:
            with open(os.devnull, "w") as dnl:
                subprocess.check_call(["pgrep", "adb"], stdout=dnl)
        except subprocess.CalledProcessError:
            # adb is not running
            try:
                # Try to start adb by calling "adb devices"
                subprocess.check_call([adb, "devices"])
            except subprocess.CalledProcessError:
                raise RuntimeError("Could not start adb (\"{}\").".format(adb))

    def __init__(self, name, adb=DEFAULT_ADB):
        """Initialise a device"""
        # Setup logging
        self.log = logging.getLogger(self.__class__.__name__)
        if not name or not adb:
            raise ValueError("Bad device name or adb value.")
        # Verify the device name
        # TODO: removing it would save time, check if we can do without
        try:
            subprocess.check_call([adb, "-s", name, "shell", "true"])
        except subprocess.CalledProcessError:
            raise ValueError("Bad device name or adb value.")
        else:
            self.log.info("Using device \"%s\".", name)
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
            self.log.warning(e)
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
        psz = subprocess.check_output(self.shell + cmd).split('\n')[1:]
        for line in psz:
            line = line.strip("\r")
            if line:
                try:
                    p = Process(line, self.android_version)
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
        listing = []
        path = os.path.normpath(path)
        cmd = ["ls", "-lRZ", "'" + path + "'"]

        # Get the File object for the top-level path
        # We could not get it otherwise
        files_dict.update(self.get_dir(path))
        # If the device is slow there can be errors produced when running down
        # /proc (ls: /proc/10/exe: No such file or directory) particularly on
        # the emulator. On exception this will just output a string containing
        # all the entries, therefore on error convert output to a list as if
        # nothing happened.
        try:
            listing = subprocess.check_output(self.shell + cmd).split('\n')
        except subprocess.CalledProcessError as e:
            listing = e.output.split('\n')

        # Parse ls -lRZ output for a directory
        # In Android <=6.0 the output of ls -lRZ "<DIRECTORY>" begins
        # with a blank line, in >=6.0.1 it doesn't.
        # This is taken care of when parsing here.
        new_dir = False
        first_run = True
        for line in listing:
            line = line.strip("\r")
            # Skip "total" line
            if line.startswith("total "):
                if first_run:
                    first_run = False
                continue
            # If the current line is empty, expect a new directory in the next
            if not line:
                new_dir = True
                if first_run:
                    first_run = False
                continue
            # Initialise new directory
            if new_dir or first_run:
                directory = line.strip(':')
                new_dir = False
                if first_run:
                    first_run = False
                continue
            # Regular line describing a file
            try:
                f = File(line, directory, self.android_version)
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
        cmd = ["ls", "-lZ", "'" + path + "'"]
        listing = subprocess.check_output(self.shell + cmd).split('\n')
        line = listing[0].strip("\r")
        # Parse ls -lZ output for a single file
        try:
            f = File(line, os.path.dirname(path), self.android_version)
        except ValueError as e:
            self.log.error(e)
            return None
        else:
            return {f.absname: f}

    def get_dir(self, path):
        """Get the directory matching the given path from a connected device.
        The path must be a directory.

        This only returns information on the single directory ("ls -ldZ"): to
        get information about all the directory content recursively, use
        get_files(path).

        Returns a dictionary (filename, File)."""
        path = os.path.normpath(path)
        cmd = ["ls", "-ldZ", "'" + path + "'"]
        listing = subprocess.check_output(self.shell + cmd).split('\n')
        line = listing[0].strip("\r")
        # Parse ls -ldZ output for a directory
        try:
            f = File(line, os.path.dirname(path), self.android_version)
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

    # Do we support Android versions newer than 6.0.1 hoping they don't
    # change the "ls -l(R)Z" output format anymore?
    SUPPORT_NEWER_VERSIONS = True
    # Android 6.0 and lower
    # -rwxrwxrwx user group context name (-> target)
    correct_line_6_0 = re.compile(
        r'[-dclpsb][-rwxst]{9}\s+(?:[^\s]+\s+){2}(?:[^\s:]+:){3,}[^\s:]+\s+.*')
    # Android 6.0.1, 7 (N Preview) and above
    # -rwxrwxrwx #links user group context size(B) date time name (-> target)
    correct_line_6_0_1 = re.compile(
        r'[-dclpsb][-rwxst]{9}\s+(?:[0-9]+)\s+(?:[^\s]+\s+){2}'
        r'(?:[^\s:]+:){3,}[^\s:]+\s+(?:[0-9]+(?:,\s+[0-9]+)?)\s+'
        r'(?:[0-9]{4}(?:-[0-9]{2}){2})\s+(?:[0-9]{2}:[0-9]{2}\s+.*)')

    def __init__(self, l, d, a_v):
        """Initialize a File.

        l   - the line in the Android ls -l(R)Z output
        d   - the directory in which the file is
        a_v - the Android version string ("5.1.1", "6.0", "N", ...)
        """
        # TODO: change the parsing to matching groups in the regexes and
        # extract parameters that way.
        # If this is an old-style file line (Android<=6.0)
        if a_v == "6.0" or (a_v[0].isdigit() and (int(a_v[0])) < 6):
            if not File.correct_line_6_0.match(l):
                raise ValueError('Bad file "{}"'.format(l))
            line = l.split(None, 4)
            # If we are processing the top-level directory, the "name" field
            # will be empty in Android <= 6.0. Use the directory name
            if len(line) == 4 and l[0] == "d":
                # Put an empty value as the "name" field
                line.append("")
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
        # If this is a new-style file line (Android>=6.0.1)
        elif a_v == "6.0.1" or File.SUPPORT_NEWER_VERSIONS:
            if not File.correct_line_6_0_1.match(l):
                raise ValueError('Bad file "{}"'.format(l))
            # If this is a character device or a block device, split the line
            # in 9 to work around the "size" being two space-separated fields
            #                                      vvvv
            # e.g. crw-rw---- 1 r i u:o_r:i_d:s0 13,  63 2016-04-08 13:57 mice
            if l[0] in "bc":
                line = l.split(None, 9)
            else:
                line = l.split(None, 8)
            self._security_class = File.file_class_converter[l[0]]
            self._dac = line[0]
            self._linkno = line[1]
            self._user = line[2]
            self._group = line[3]
            self._context = Context(line[4])
            # If the file is a character device or a block device, this is not
            # the size, but the driver number
            if l[0] in "bc":
                self._size = line[5] + " " + line[6]
                # Remove the 6th argument after we're done, this way the list
                # only goes to 8 and we don't need to change the numbering
                # below
                line.pop(6)
            else:
                self._size = line[5]
            self._lastdate = line[6]
            self._lasttime = line[7]
            if self._security_class == "lnk_file" and "->" in line[8]:
                # If it is a symlink it has a target
                self._basename, self._target = line[8].split(" -> ")
            else:
                self._basename = line[8]
            self._path = d
            self._absname = os.path.join(self._path, self._basename)
        else:
            raise NotImplementedError("Unsupported Android version.")

    @property
    def security_class(self):
        """Get the file class"""
        return self._security_class

    @property
    def dac(self):
        """Get the file DAC permission string"""
        return self._dac

    @property
    def linkno(self):
        """Get the number of links to the file, if available."""
        if hasattr(self, "_linkno"):
            return self._linkno
        else:
            return None

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
    def size(self):
        """Get the file size in Bytes, if available."""
        if hasattr(self, "_size"):
            return self._size
        else:
            return None

    @property
    def lastdate(self):
        """Get the file last modifed date, if available."""
        if hasattr(self, "_lastdate"):
            return self._lastdate
        else:
            return None

    @property
    def lasttime(self):
        """Get the file last modified time, if available."""
        if hasattr(self, "_lasttime"):
            return self._lasttime
        else:
            return None

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
        return self._security_class == "lnk_file"

    def is_directory(self):
        """Returns True if the file is a directory, False otherwise"""
        return self._security_class == "dir"

    def __repr__(self):
        return self.absname

    def __eq__(self, other):
        return self.absname == other.absname

    def __lt__(self, other):
        return self.absname < other.absname

    def __le__(self, other):
        return self.absname <= other.absname

    def __ne__(self, other):
        return self.absname != other.absname

    def __gt__(self, other):
        return self.absname > other.absname

    def __ge__(self, other):
        return self.absname >= other.absname

    def __hash__(self):
        return hash(self.absname)


class Process(object):
    """Class providing an abstraction for a process on the device"""
    # Do we support Android versions newer than 6.0.1 hoping they don't
    # change the "ps -Z" output format anymore?
    SUPPORT_NEWER_VERSIONS = True
    # Android 6.0 and previous: LABEL USER PID PPID NAME
    correct_line_6_0 = re.compile(
        r'(?:[^\s:]+:){3,}[^\s:]+\s+[^\s]+\s+[0-9]+\s+[0-9]+\s+[^\s]+.*')
    # Android 6.0.1: LABEL USER PID PPID VSIZE RSS WCHAN PC STATUS NAME
    correct_line_6_0_1 = re.compile(
        r'(?:[^\s:]+:){3,}[^\s:]+\s+[^\s]+\s+(?:[0-9]+\s+){4}[^\s]+\s+[0-9a-f]+\s+[A-Z]\s+[^\s]+.*')

    def __init__(self, line, a_v):
        """Initialize a Process.

        line    - the line in the Android ps -Z output
        a_v     - the Android version string ("5.1.1", "6.0", "N", ...)
        """
        # If this is an old-style process line (Android<=6.0)
        if a_v == "6.0" or (a_v[0].isdigit() and (int(a_v[0])) < 6):
            if not Process.correct_line_6_0.match(line):
                raise ValueError('Bad process "{}"'.format(line))
            p = line.split(None, 4)
            self._context = Context(p[0])
            self._user = p[1]
            self._pid = p[2]
            self._ppid = p[3]
            self._name = p[4]
        # If this is a new-style process line (Android>=6.0.1)
        elif a_v == "6.0.1" or Process.SUPPORT_NEWER_VERSIONS:
            if not Process.correct_line_6_0_1.match(line):
                raise ValueError('Bad process "{}"'.format(line))
            p = line.split(None, 9)
            self._context = Context(p[0])
            self._user = p[1]
            self._pid = p[2]
            self._ppid = p[3]
            self._vsize = p[4]
            self._rss = p[5]
            self._wchan = p[6]
            self._pc = p[7]
            self._status = p[8]
            self._name = p[9]
        else:
            raise NotImplementedError("Unsupported Android version.")

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
    def vsize(self):
        """Get the process VSIZE"""
        if hasattr(self, "_vsize"):
            return self._vsize
        else:
            return None

    @property
    def rss(self):
        """Get the process RSS"""
        if hasattr(self, "_rss"):
            return self._rss
        else:
            return None

    @property
    def wchan(self):
        """Get the process WCHAN"""
        if hasattr(self, "_wchan"):
            return self._wchan
        else:
            return None

    @property
    def pc(self):
        """Get the process PC"""
        if hasattr(self, "_pc"):
            return self._pc
        else:
            return None

    @property
    def status(self):
        """Get the process status"""
        if hasattr(self, "_status"):
            return self._status
        else:
            return None

    @property
    def name(self):
        """Get the process name"""
        return self._name

    def __repr__(self):
        return "{} {}".format(self.pid, self.name)

    def __eq__(self, other):
        return self.pid == other.pid

    def __lt__(self, other):
        return int(self.pid) < int(other.pid)

    def __le__(self, other):
        return int(self.pid) <= int(other.pid)

    def __ne__(self, other):
        return self.pid != other.pid

    def __gt__(self, other):
        return int(self.pid) > int(other.pid)

    def __ge__(self, other):
        return int(self.pid) >= int(other.pid)

    def __hash__(self):
        return int(self.pid)
