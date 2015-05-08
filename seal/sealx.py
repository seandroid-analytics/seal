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

"""The SELinux Analytics Library graphic frontend"""

from Tkinter import *
from ttk import *
import tkSimpleDialog
import tkMessageBox
import threading

import seal

class DevicePicker(tkSimpleDialog.Dialog):
    """A device picker popup"""
    def body(self, master):
        self.focus_set()
        Label(master, text="Select a device:").grid(row=0, column=0, sticky=W+N)
        devices = seal.get_devices()
        if not devices:
            print "No devices connected"
            tkMessageBox.showerror("Fatal error", "No devices connected")
            master.quit()
        self.devices_cb = Combobox(master, state='readonly', values=devices,
                width=len(max(devices, key=len))-20)
        self.devices_cb.grid(row=1, column=0, sticky=N+S+E+W)
        self.devices_cb.current(0)
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(1, weight=1)

    def apply(self):
        value = self.devices_cb.get()
        self.result = value

###############################################################################
# Taken from https://stackoverflow.com/questions/3781670/how-to-highlight-text-in-a-tkinter-text-widget
class SearchableText(Text):
    '''A searchable and highlightable Text widget

    The highlight_pattern method is a simplified python
    version of the tcl code at http://wiki.tcl.tk/3246
    '''
    def __init__(self, *args, **kwargs):
        Text.__init__(self, *args, **kwargs)
        self.tag_config("highlight", background="#ffff00")
        self.tag_config('evenrow', background='#efefef')
        # Which tag has precedence
        # 'evenrow' < 'highlight' < 'sel'
        self.tag_raise('highlight')
        self.tag_raise("sel")

    def highlight_odd_lines(self):
        """Apply a light gray color to odd lines
        to make the text more readable"""
        end = int(self.index('end-1c').split('.')[0])
        for i in range(2, end):
            if i % 2 == 0:
                self.tag_add('evenrow', "{}.0".format(i),
                        "{}.0".format(i+1))

    def highlight_pattern(self, pattern, start="1.0", end="end", regexp=False):
        '''Apply the given tag to all text that matches the given pattern
        If 'regexp' is set to True, pattern will be treated as a regular
        expression.
        '''
        start = self.index(start)
        end = self.index(end)
        self.mark_set("matchStart", start)
        self.mark_set("matchEnd", start)
        self.mark_set("searchLimit", end)

        count = IntVar()
        while True:
            index = self.search(pattern, "matchEnd", "searchLimit",
                    count=count, regexp=regexp)
            if index == "":
                break
            self.mark_set("matchStart", index)
            self.mark_set("matchEnd", "%s+%sc" % (index, count.get()))
            self.tag_add('highlight', "matchStart", "matchEnd")
###############################################################################

class App(Frame):
    """The main application window"""
    def __init__(self, master):
        Frame.__init__(self, master)
        self.master = master
        master.wm_title("SEAL - SEAndroid Analytics Library")
        self.device_string = StringVar()
        self.androidver_string = StringVar()
        self.selinux_string = StringVar()
        self.policy_string = StringVar()
        self.fileno_string = StringVar()
        self.procno_string = StringVar()
        self.filteringby_string = StringVar()
        self.processcontext_string = StringVar()
        self.searchresno_string = StringVar()
        self.first_progressbar = True

        self.body(master)
        # Check adb
        if not seal.check_adb():
            tkMessageBox.showerror("Fatal error", "Failed to start adb")
            self.quit()
        # Choose device
        self.device_picker = DevicePicker(self.master, "SEAL - Device picker")
        if self.device_picker.result is None:
            # Disable everything when you have a queue
            # For now just quit
            master.quit()
        #TODO: Improve device name selection
        self.device = self.device_picker.result.split()[0]
        self.device_string.set("Device: {}".format(self.device))
        self.root_adb = seal.check_root_adb(self.device)
        if self.root_adb == "not_root":
            print "WARNING: Adb can not run as root on the device."
            print "The information shown by the tool will be incomplete."
            tkMessageBox.showwarning("ADB is not root",
                    "Adb can not run as root on the selected device.\n"
                    "The information shown by the tool will be incomplete.")

        self.androidver_string.set("Android version: {}".format(
                seal.get_android_version(self.device)))
        self.selinux_string.set("SELinux mode: {}".format(
                seal.get_selinux_mode(self.device).lower()))
        # Setup policy
        self.policy = seal.setup_policy(None, self.device)
        if self.policy is None:
            tkMessageBox.showerror("Fatal error" "Failed to initialise policy")
            self.quit()
        self.policy_string.set("Policy: {}".format(self.policy.name))
        # Setup processes
        self.processes = seal.get_processes(self.device)
        max_pid_len = len(max(self.processes, key=len))
        self.processes_lb.config(width=max_pid_len + 2 + len(
                max([i.name for i in self.processes.values()], key=len)))
        self.processes_lb.insert('end', "No filter".rjust(9 + max_pid_len))
        for i in sorted(self.processes.values(), key=lambda x: int(x.pid)):
            self.processes_lb.insert('end',
                    "{} {}".format(i.pid.rjust(max_pid_len), i.name))
        self.processes_lb.config(state=DISABLED)
        self.files_search_button.config(state=DISABLED)
        self.files_search_entry.config(state=DISABLED)
        self.processes_filterbyfile_button.config(state=DISABLED)
        self.processes_filterbyfile_entry.config(state=DISABLED)
        self.procno_string.set("Processes: {}".format(len(self.processes)))
        self.processes_filter_by_file()
        # Get files
        self.filteringby_string.set("files")
        self.show_progressbar()
        self.worker_thread = threading.Thread(
                target=self.get_files_bg, args=[self.device])
        self.worker_thread.start()
        self.after(100, self.worker_callback)

    def get_files_bg(self, device, path='/'):
        """Get the file list from the device"""
        self.files = seal.get_files(device, path)

    def worker_callback(self):
        """Callback when the file list has been fetched from the device"""
        if self.worker_thread.is_alive():
            self.after(100, self.worker_callback)
        else:
            self.hide_progressbar()
            self.fileno_string.set("Files: {}".format(len(self.files.keys())))
            self.filter_files(None)
            self.processes_lb.config(state=NORMAL)
            self.files_search_button.config(state=NORMAL)
            self.files_search_entry.config(state=NORMAL)
            self.processes_filterbyfile_button.config(state=NORMAL)
            self.processes_filterbyfile_entry.config(state=NORMAL)

    def filter_files(self, process):
        """Filter files by process in a background thread"""
        self.filter_thread = threading.Thread(
                target=self.filter_files_bg, args=[process])
        self.filter_thread.start()
        self.after(200, self.filter_callback)

    def filter_files_bg(self, process):
        """Filter files by a given process"""
        result = seal.files_filter(self.policy, process, self.files)
        self.accessible_files = result[0]
        self.file_permissions = result[1]

    def filter_callback(self):
        """Callback when the files have been filtered by process"""
        if self.filter_thread.is_alive():
            self.after(200, self.filter_callback)
        else:
            self.hide_progressbar()
            self.view_files(self.accessible_files, self.file_permissions)

    def menu_lost_focus(self, event):
        """Unpost a menu when it loses focus"""
        menu = event.widget
        menu.unpost()

    def show_menu(self, event, menu):
        """Show a contextual menu with dynamic actions"""
        if menu is self.files_rmenu:
            self.files_rmenu.entryconfigure("Find processes",
                    command=lambda event=event: self.files_show_processes(event))
            self.files_rmenu.entryconfigure("Copy", state=DISABLED)
            if self.files_text.tag_ranges("sel"):
                self.files_rmenu.entryconfigure("Copy", state=NORMAL)
        if menu is self.processes_rmenu:
            self.processes_rmenu.entryconfigure("Find files",
                    command=lambda event=event: self.processes_show_files(event))
            self.processes_rmenu.entryconfigure("Copy", state=DISABLED)
            if self.processes_text.tag_ranges("sel"):
                self.processes_rmenu.entryconfigure("Copy", state=NORMAL)
        menu.post(event.x_root, event.y_root)
        menu.focus_set()

    def files_show_processes(self, event):
        """When right-clicking a file, give the option to show
        the processes that can access it"""
        index = event.widget.index("@%s,%s" % (event.x, event.y))
        line = index.split(".")[0]
        filename = self.files_text.get(
                "{}.0".format(line), "{}.0-1c".format(int(line)+1))
        if filename in self.files:
            self.tabs.select(self.processes_tab)
            self.processes_filterbyfile_entry.delete(0, END)
            self.processes_filterbyfile_entry.insert(0, filename)
            self.processes_filter_by_file()

    def view_files(self, files, permissions=None):
        """Display the textview with the file list"""
        self.files_search_entry.delete(0, END) # Delete the search parameter
        self.files_text.config(state=NORMAL)
        self.files_text.delete(1.0, END)
        self.files_current_files = []
        for lst in files.values():
            for f in lst:
                self.files_text.insert(END, "{}".format(f.absname))
                self.files_text.insert(END, "\n")
                self.files_current_files.append(f)
        self.files_text.highlight_odd_lines()
        self.files_text.config(state=DISABLED)
        self.filteringby_string.set("{} {}".format(
                len(self.files_current_files), self.filteringby_string.get()))

    def view_process_details(self, event):
        """When clicking on a process in the processes tab,
        give some details about the process"""
        self.processes_text.focus_set()

    def view_file_details(self, event):
        """When clicking on a file in the files tab,
        give some details about the file"""
        self.files_text.focus_set()
        index = self.files_text.index("@%s,%s" % (event.x, event.y))
        line = index.split(".")[0]
        # Close the menu
        self.files_rmenu.unpost()
        filename = self.files_text.get(
                "{}.0".format(line), "{}.0-1c".format(int(line)+1))
        if filename in self.files:
            f = self.files[filename]
            self.files_details_text.config(state=NORMAL)
            self.files_details_text.delete(1.0, END)
            self.files_details_text.insert(END, 'Details about "{}":\n'.format(f.absname))
            self.files_details_text.insert(END, "UNIX permissions: {}\n".format(f.dac))
            self.files_details_text.insert(END, "User: {}\nGroup: {}\n".format(f.user, f.group))
            self.files_details_text.insert(END, "\nSELinux information:\n")
            self.files_details_text.insert(END, "File type: {}\n".format(f.security_class))
            self.files_details_text.insert(END, "SELinux user: {}\n".format(f.context.user))
            self.files_details_text.insert(END, "SELinux role: {}\n".format(f.context.role))
            self.files_details_text.insert(END, "SELinux type: {}\n".format(f.context.type))
            self.files_details_text.insert(END, "SELinux sensitivity: {}\n".format(f.context.sens))
            if f in self.file_permissions:
                self.files_details_text.insert(END, 'Permissions on "{}" by "{}":'.format(
                    f.absname, self.current_filter_process.name))
                for p in self.file_permissions[f]:
                    self.files_details_text.insert(END, '\n{}'.format(p))
            self.files_details_text.config(state=DISABLED)

    def filter_proc(self, event=None):
        """Show files accessible by a process"""
        self.show_progressbar()
        value = self.processes_lb.get(ACTIVE)
        self.processes_lb.selection_clear(1, END)
        self.processes_lb.selection_set(ACTIVE)
        if "No filter" in value:
            print "Showing all files"
            process = None
            self.filteringby_string.set("files")
            self.processcontext_string.set('')
        else:
            process = self.processes[value.split()[0].strip()]
            print "Filtering by process: {}".format(value)
            self.filteringby_string.set(
                    'files accessible by process "{}"'.format(process.name))
            self.processcontext_string.set(
                    'running in SELinux domain "{}" (context: "{}")'.format(
                    process.context.type, process.context))
        self.current_filter_process = process
        self.filter_files(process)

    def processes_show_files(self, event=None):
        """When right clicking on a process in the process tab,
        give the option to list the files it has access to"""
        index = event.widget.index("@%s,%s" % (event.x, event.y))
        line = index.split(".")[0]
        l = self.processes_text.get(
                "{}.0".format(line), "{}.0-1c".format(int(line)+1))
        pid = l.split()[0]
        if pid in self.processes:
            self.tabs.select(self.file_tab)
            self.processes_lb.focus_set()
            for i in range(self.processes_lb.size()):
                if pid == self.processes_lb.get(i).split()[0]:
                    # We want to filter by element i
                    self.processes_lb.activate(i)
                    self.filter_proc()

    def file_search(self, event=None):
        """Search for a string in the file list"""
        s = self.files_search_entry.get()
        if s: # Search pattern
            fl = []
            for f in self.files_current_files:
                if s in f.absname:
                    fl.append(f)
            self.searchresno_string.set("{} files matching".format(len(fl)))
        else: # Clear search
            fl = self.files_current_files
            self.searchresno_string.set("")

        self.files_text.config(state=NORMAL)
        self.files_text.delete(1.0, END)
        for f in fl:
            self.files_text.insert(END, "{}".format(f.absname))
            self.files_text.insert(END, "\n")

        self.files_text.highlight_odd_lines()
        if s:
            self.files_text.highlight_pattern(s)
        self.files_text.config(state=DISABLED)

    def show_progressbar(self):
        """Show an active progressbar in the status bar, with automatic width"""
        self.update_idletasks()
        l = (self.status_bar.winfo_width() -
            self.device_label.winfo_width() -
            self.selinux_label.winfo_width() -
            self.androidver_label.winfo_width() -
            self.policy_label.winfo_width() -
            self.fileno_label.winfo_width() -
            self.procno_label.winfo_width() -
            15)
        self.progressbar.config(length=l)
        if self.first_progressbar:
            self.progressbar.grid(row=0, column=11, sticky=E)
            self.first_progressbar = False
        else:
            self.progressbar.grid()
        self.progressbar.start()

    def hide_progressbar(self):
        """Stop and hide the progress bar from the status bar"""
        self.progressbar.stop()
        self.progressbar.grid_remove()

    def processes_filter_by_file(self, event=None):
        """Given a file, list all processes that can access it.
        Given a path, list all processes that can access any
        item in that subtree"""
        filename = self.processes_filterbyfile_entry.get()
        if filename and filename in self.files: # Filter by file
            f = self.files[filename]
            files = {}
            if f.is_directory():
                for i in self.files.values():
                    if i.absname.startswith(f.absname):
                        files[i.absname] = i
            else:
                files[f.absname] = f

            result = seal.processes_filter(self.policy, files, self.processes)
            self.allowed_processes_by_file = result[0]
            self.process_permissions_by_file = result[1]
            self.processes_text.config(state=NORMAL)
            self.processes_text.delete('1.0', END)
            for f2 in sorted(self.allowed_processes_by_file.keys()):
                p2 = self.allowed_processes_by_file[f2]
                self.processes_text.insert(END,
                        'The {} "{}" in the context "{}" can be accessed by {} processes:'.format(
                        f2.security_class, f2, f2.context, len(p2)))
                max_pid_len = max([len(str(x.pid)) for x in p2])
                for p in sorted(p2):
                    self.processes_text.insert(END, '\n{} {}'.format(
                            p.pid.rjust(max_pid_len+2), p.name))
                self.processes_text.insert(END, '\n')
            self.processes_text.highlight_odd_lines()
            self.processes_text.config(state=DISABLED)
        elif not filename: # Clear filter
            self.processes_text.config(state=NORMAL)
            self.processes_text.delete('1.0', END)
            max_pid_len = max([len(str(x.pid)) for x in self.processes.values()])
            for p in sorted(self.processes.values()):
                self.processes_text.insert(END,
                        '{} {}\n'.format(p.pid.rjust(max_pid_len+2), p.name))
            self.processes_text.highlight_odd_lines()
            self.processes_text.config(state=DISABLED)

    def body(self, master):
        """Build the body of the main app window"""
        self.tabs = Notebook(master)
        ######################################################################
        # File tab
        ##########
        self.file_tab = Frame(self.tabs)
        # Left part
        self.processes_frame = LabelFrame(self.file_tab,
                padding=(5, 5, 5, 5), text="Processes")
        Label(self.processes_frame, text="Double click a process",
                padding=(5, 5, 5, 5)).grid(row=0, sticky=W)
        scrollbar = Scrollbar(self.processes_frame, orient='vertical')
        self.processes_lb = Listbox(self.processes_frame,
                yscrollcommand=scrollbar.set,
                selectmode='single',
                font='TkFixedFont',
                exportselection=0)
        self.processes_lb.bind("<Double-Button-1>", self.filter_proc)
        self.processes_lb.bind("<Return>", self.filter_proc)
        scrollbar.config(command=self.processes_lb.yview)
        # Status bar
        self.status_bar = Frame(master)
        self.device_label = Label(self.status_bar,
                textvariable=self.device_string,
                relief='sunken', anchor='w')
        self.androidver_label = Label(self.status_bar,
                textvariable=self.androidver_string,
                relief='sunken', anchor='w')
        self.policy_label = Label(self.status_bar,
                textvariable=self.policy_string,
                relief='sunken', anchor='w')
        self.selinux_label = Label(self.status_bar,
                textvariable=self.selinux_string,
                relief='sunken', anchor='w')
        self.fileno_label = Label(self.status_bar,
                textvariable=self.fileno_string,
                relief='sunken', anchor='w')
        self.procno_label = Label(self.status_bar,
                textvariable=self.procno_string,
                relief='sunken', anchor='w')
        self.progressbar = Progressbar(self.status_bar,
                orient="horizontal", mode="indeterminate")
        # Right part
        self.files_frame = LabelFrame(self.file_tab,
                padding=(5, 5, 5, 5), text="Files")
        ## Info bar
        self.files_infobar = Frame(self.files_frame)
        Label(self.files_infobar, textvariable=self.filteringby_string,
                padding=(0, 0, 5, 0)).grid(row=0, column=0, sticky=W)
        Label(self.files_infobar, textvariable=self.processcontext_string,
                padding=(0, 0, 5, 0)).grid(row=0, column=1, sticky=W)
        ## Search bar
        self.files_searchbar = Frame(self.files_frame)
        Label(self.files_searchbar, textvariable=self.searchresno_string
                ).grid(row=0, column=0, sticky=W)
        self.files_search_button = Button(self.files_searchbar,
                text="Search", command=self.file_search)
        self.files_search_entry = Entry(self.files_searchbar)
        self.files_search_entry.bind('<Return>', self.file_search)
        self.files_search_entry_rmenu = Menu(tearoff=0)
        self.files_search_entry_rmenu.add_command(label="Cut",
                command=lambda: self.files_search_entry.event_generate("<<Cut>>"))
        self.files_search_entry_rmenu.add_command(label="Copy",
                command=lambda: self.files_search_entry.event_generate("<<Copy>>"))
        self.files_search_entry_rmenu.add_command(label="Paste",
                command=lambda: self.files_search_entry.event_generate("<<Paste>>"))
        self.files_search_entry.bind("<3>",
                lambda event: self.show_menu(event, self.files_search_entry_rmenu))
        self.files_search_entry_rmenu.bind("<FocusOut>", self.menu_lost_focus)
        self.files_search_entry_rmenu.bind("<Escape>", self.menu_lost_focus)
        ## Files text
        files_scrollv = Scrollbar(self.files_frame, orient='vertical')
        files_scrollh = Scrollbar(self.files_frame, orient='horizontal')
        self.files_text = SearchableText(self.files_frame,
                wrap=NONE,
                yscrollcommand=files_scrollv.set,
                xscrollcommand=files_scrollh.set,
                font='TkFixedFont')
        self.files_text.bind("<1>", self.view_file_details)
        files_scrollv.config(command=self.files_text.yview)
        files_scrollh.config(command=self.files_text.xview)
        ### Files right click menu
        self.files_rmenu = Menu(tearoff=0)
        self.files_rmenu.add_command(label="Copy",
                command=lambda: self.files_text.event_generate("<<Copy>>"))
        self.files_rmenu.add_command(label="Find processes")
        self.files_text.bind("<3>",
                lambda event: self.show_menu(event, self.files_rmenu))
        self.files_rmenu.bind("<FocusOut>", self.menu_lost_focus)
        self.files_rmenu.bind("<Escape>", self.menu_lost_focus)
        ## File detail text
        details_scrollv = Scrollbar(self.files_frame, orient='vertical')
        details_scrollh = Scrollbar(self.files_frame, orient='horizontal')
        self.files_details_text = SearchableText(self.files_frame,
                wrap=NONE,
                yscrollcommand=details_scrollv.set,
                xscrollcommand=details_scrollh.set,
                font='TkFixedFont')
        details_scrollv.config(command=self.files_details_text.yview)
        details_scrollh.config(command=self.files_details_text.xview)

        # Grid configuration
        # Global
        self.file_tab.grid_rowconfigure(1, weight=1)
        # Left part
        self.processes_frame.grid_rowconfigure(1, weight=1)
        self.processes_frame.grid(row=1, column=0, sticky=N+S+W+E, padx=5, pady=5)
        self.processes_lb.grid(row=1, column=0, sticky=N+S+W+E)
        scrollbar.grid(row=1, column=1, sticky=N+S)
        # Right part
        self.files_frame.grid(row=1, column=1, sticky=N+S+W+E, padx=5, pady=5)
        self.file_tab.grid_columnconfigure(1, weight=1)
        self.files_frame.grid_rowconfigure(2, weight=1)
        ## Info bar
        self.files_infobar.grid(row=0, column=0, columnspan=4, sticky=N+S+W+E)
        ## Search bar
        self.files_searchbar.grid(row=1, column=0, columnspan=4, sticky=N+S+W+E)
        self.files_searchbar.grid_columnconfigure(1, weight=1)
        self.files_search_entry.grid(row=0, column=1, sticky=N+S+W+E)
        self.files_search_button.grid(row=0, column=2, sticky=N+S+E)
        ## Files Text
        self.files_text.grid(row=2, column=0, sticky=N+S+W+E)
        self.files_frame.grid_columnconfigure(0, weight=2)
        files_scrollv.grid(row=2, column=1, sticky=N+S)
        files_scrollh.grid(row=3, column=0, sticky=E+W)
        ## Files details Text
        self.files_details_text.grid(row=2, column=2, sticky=N+S+W+E)
        self.files_frame.grid_columnconfigure(2, weight=1)
        details_scrollv.grid(row=2, column=3, sticky=N+S)
        details_scrollh.grid(row=3, column=2, sticky=E+W)
        # Status bar
        self.device_label.grid(row=0, column=0, sticky=W)
        Separator(self.status_bar).grid(row=0, column=1, sticky=N+S)
        self.androidver_label.grid(row=0, column=2, sticky=W)
        Separator(self.status_bar).grid(row=0, column=3, sticky=N+S)
        self.selinux_label.grid(row=0, column=4, sticky=W)
        Separator(self.status_bar).grid(row=0, column=5, sticky=N+S)
        self.policy_label.grid(row=0, column=6, sticky=W)
        Separator(self.status_bar).grid(row=0, column=7, sticky=N+S)
        self.procno_label.grid(row=0, column=8, sticky=W)
        Separator(self.status_bar).grid(row=0, column=9, sticky=N+S)
        self.fileno_label.grid(row=0, column=10, sticky=W)

        self.tabs.add(self.file_tab, text="Files")
        #######################################################################
        # Processes tab
        #############
        self.processes_tab = Frame(self.tabs)
        # Search bar
        self.processes_file_searchbar = Frame(self.processes_tab)
        Label(self.processes_file_searchbar, text="Filter processes by file",
                padding=(5, 5, 5, 5)).grid(row=0, column=0, sticky=W)
        self.processes_filterbyfile_button = Button(self.processes_file_searchbar,
                text="Filter", command=self.processes_filter_by_file)
        self.processes_filterbyfile_entry = Entry(self.processes_file_searchbar)
        self.processes_filterbyfile_entry.bind('<Return>',
                self.processes_filter_by_file)
        self.processes_filterbyfile_entry_rmenu = Menu(tearoff=0)
        self.processes_filterbyfile_entry_rmenu.add_command(label="Cut",
                command=lambda: self.processes_filterbyfile_entry.event_generate("<<Cut>>"))
        self.processes_filterbyfile_entry_rmenu.add_command(label="Copy",
                command=lambda: self.processes_filterbyfile_entry.event_generate("<<Copy>>"))
        self.processes_filterbyfile_entry_rmenu.add_command(label="Paste",
                command=lambda: self.processes_filterbyfile_entry.event_generate("<<Paste>>"))
        self.processes_filterbyfile_entry.bind("<3>", lambda event:
                self.show_menu(event, self.processes_filterbyfile_entry_rmenu))
        self.processes_filterbyfile_entry_rmenu.bind("<FocusOut>",
                self.menu_lost_focus)
        self.processes_filterbyfile_entry_rmenu.bind("<Escape>",
                self.menu_lost_focus)
        # Processes text
        self.processes_text_frame = Frame(self.processes_tab)
        processes_scrollv = Scrollbar(self.processes_text_frame,
                orient='vertical')
        processes_scrollh = Scrollbar(self.processes_text_frame,
                orient='horizontal')
        self.processes_text = SearchableText(self.processes_text_frame,
                wrap=NONE,
                yscrollcommand=processes_scrollv.set,
                xscrollcommand=processes_scrollh.set,
                font='TkFixedFont')
        self.processes_text.bind("<1>", self.view_process_details)
        processes_scrollv.config(command=self.processes_text.yview)
        processes_scrollh.config(command=self.processes_text.xview)
        ## Processes right click menu
        self.processes_rmenu = Menu(tearoff=0)
        self.processes_rmenu.add_command(label="Copy", command=lambda:
                self.processes_text.event_generate("<<Copy>>"))
        self.processes_rmenu.add_command(label="Find files")
        self.processes_text.bind("<3>",
                lambda event: self.show_menu(event, self.processes_rmenu))
        self.processes_rmenu.bind("<FocusOut>", self.menu_lost_focus)
        self.processes_rmenu.bind("<Escape>", self.menu_lost_focus)
        # Grid c:wonfiguration
        # Global
        self.processes_tab.grid_rowconfigure(1, weight=1)
        self.processes_tab.grid_columnconfigure(0, weight=1)
        self.processes_file_searchbar.grid(row=0, column=0, sticky=N+S+W+E)
        self.processes_text_frame.grid(row=1, column=0, sticky=N+S+W+E)
        # Processes file searchbar
        self.processes_file_searchbar.grid_columnconfigure(1, weight=1)
        self.processes_filterbyfile_entry.grid(row=0, column=1, sticky=N+S+W+E)
        self.processes_filterbyfile_button.grid(row=0, column=2, sticky=N+S+W+E)
        # Processes text frame
        self.processes_text_frame.grid_columnconfigure(0, weight=1)
        self.processes_text_frame.grid_rowconfigure(0, weight=1)
        self.processes_text.grid(row=0, column=0, sticky=N+S+W+E)
        processes_scrollv.grid(row=0, column=1, sticky=N+S)
        processes_scrollh.grid(row=1, column=0, sticky=E+W)

        self.tabs.add(self.processes_tab, text="Processes")
        #######################################################################
        # Final
        #######
        self.tabs.pack(expand=1, fill='both')
        self.status_bar.pack(fill='x')

def main():
    """The main function"""
    root = Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
