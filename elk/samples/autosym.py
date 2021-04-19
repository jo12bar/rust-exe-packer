# /usr/bin/env python3
#
# autosym.py
#
# Load symbols from memory-mapped files into GDB.
#

import subprocess

pid = gdb.selected_inferior().pid

cmd = ["elk", "autosym", "%d" % pid]
lines = subprocess.check_output(cmd).decode("utf-8").split("\n")

for line in lines:
    gdb.execute(line)
