#!/usr/bin/env python
#
# Copyright (c) 2015, Assured Information Security, Inc.
#
# Author: Chris Patterson <pattersonc@ainfosec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import dbus
import sys
import json

### Compatibility glue for insane dump (ala db-ls)
def dump(obj, path):
    key_name = ""
    for elem in path.split("/"):
        if len(elem) > 0:
            key_name = elem
            break

    outstr = []
    def __path_dump_level(outstr, key_name, obj, level):
        # handle the invalid key case
        if obj == 'null':
            outstr.append("%s%s = \"\"" % (" " * level, key_name))
            return

        # simple key value
        if isinstance(obj, basestring) or isinstance(obj, bool):
            outstr.append("%s%s = \"%s\"" % (" " * level, key_name, str(obj)))
            return

        # iterate over dicts
        if isinstance(obj, dict):
            outstr.append("%s%s =" % (" " * level, key_name))
            for k, v in obj.iteritems():
                __path_dump_level(outstr, k, v, level + 1)

    __path_dump_level(outstr, key_name, obj, 0)
    return "\n".join(outstr)   

def main():
    if len(sys.argv) < 2:
        key = "/"
    else:
        key = sys.argv[1]

    bus = dbus.SystemBus()
    dbd = bus.get_object('com.citrix.xenclient.db', '/')
    iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
    data = iface.dump(key)
    obj = json.loads(data)
    out = dump(obj, key)
    print("%s" % (out))

if __name__ == "__main__":
    main()
