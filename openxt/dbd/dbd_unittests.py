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

import unittest
import shutil
import os
import dbus
import sys
import json
import subprocess

class TestDBD(unittest.TestCase):
    def test_nodes(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        root = "/"
        keys = ['t1', '/t2', 't3', 't4']
        for i, key in enumerate(keys):
            self.assertEqual(iface.write(key, "value"), None)
            self.assertEqual(len(iface.list(root)), i+1)
        self.assertEqual(iface.rm(root), None)
        self.assertEqual(iface.dump('/'), '{}')

        root = "/vm"
        keys = ['/vm/uuid/t1', '/vm/uuid2/t2', '/vm/uuid3/t3', '/vm/uuid4/t4']
        for i, key in enumerate(keys):
            self.assertEqual(iface.write(key, "value"), None)
            self.assertEqual(len(iface.list(root)), i+1)
        self.assertEqual(iface.rm(root), None)
        self.assertEqual(iface.dump('/'), '{}')

        root = "/dom-store"
        keys = ['/dom-store/uuid/t1', '/dom-store/uuid2/t2']
        for i, key in enumerate(keys):
            self.assertEqual(iface.write(key, "value"), None)
            self.assertEqual(len(iface.list(root)), i+1)

        # cleanup
        self.assertEqual(iface.rm(root), None)
        self.assertEqual(iface.dump('/'), '{}')

    def test_invreads(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        tuples =  [("d0", "/d0", "d0val"),
                   ("d0x", "d0x", "d0xval"),
                   ("d1", "/d1/d1", "d1val"),
                   ("d1x", "d1x/d1x", "d1xval"),
                   ("d2", "/d2/d2/d2", "d2val"),
                   ("d3", "/d3/d3/d3/d3", "d3val"),
                   ("d4", "/d4/d4/d4/d4/d4", "d4val"),
                   ("vm", "/vm/uuid/foo", "vmval"),
                   ("vm", "vm/uuid2/foo/d2", "vmval2"),
                   ("dom-store", "/dom-store/uuid/foo", "dval"),
                   ("dom-store", "dom-store/uuid/foo", "dval2")]
        for root, key, val in tuples:
            self.assertEqual(iface.write(key, val), None)
            self.assertEqual(iface.read(key+"xxx"), '')
            self.assertEqual(iface.rm(root), None)
            self.assertEqual(iface.dump('/'), '{}')

    def test_reads(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        tuples =  [("d0", "/d0", "d0val"),
                   ("d0x", "d0x", "d0xval"),
                   ("d1", "/d1/d1", "d1val"),
                   ("d1x", "d1x/d1x", "d1xval"),
                   ("d2", "/d2/d2/d2", "d2val"),
                   ("d3", "/d3/d3/d3/d3", "d3val"),
                   ("d4", "/d4/d4/d4/d4/d4", "d4val"),
                   ("vm", "/vm/uuid/foo", "vmval"),
                   ("vm", "vm/uuid2/foo/d2", "vmval2"),
                   ("dom-store", "/dom-store/uuid/foo", "dval"),
                   ("dom-store", "dom-store/uuid/foo", "dval2")]
        for root, key, val in tuples:
            self.assertEqual(iface.write(key, val), None)
            self.assertEqual(iface.read(key), val)
            self.assertEqual(iface.rm(root), None)
            self.assertEqual(iface.dump('/'), '{}')

    def test_exists(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        tuples =  [("d0", "/d0", "d0val"),
                   ("d0x", "d0x", "d0xval"),
                   ("d1", "/d1/d1", "d1val"),
                   ("d1x", "d1x/d1x", "d1xval"),
                   ("d2", "/d2/d2/d2", "d2val"),
                   ("d3", "/d3/d3/d3/d3", "d3val"),
                   ("d4", "/d4/d4/d4/d4/d4", "d4val"),
                   ("vm", "/vm/uuid/foo", "vmval"),
                   ("vm", "vm/uuid2/foo/d2", "vmval2"),
                   ("dom-store", "/dom-store/uuid/foo", "dval"),
                   ("dom-store", "dom-store/uuid/foo", "dval2")]
        for root, key, val in tuples:
            self.assertEqual(iface.write(key, val), None)
            self.assertEqual(iface.exists(key), True)
            self.assertEqual(iface.exists(key + "invalid"), False)

        # cleanup
        self.assertEqual(iface.rm("/"), None)
        self.assertEqual(iface.dump('/'), '{}')

    def test_dump(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        val = '{"a": "5", "c": {"c2": "1", "c1": "0"}, "b": "xxx"}'
        val = json.loads(val)
        val = json.dumps(val, indent=4, sort_keys=True)

        self.assertEqual(iface.write('a', '5'), None)
        self.assertEqual(iface.write('b', 'xxx'), None)
        self.assertEqual(iface.write('c/c1', '0'), None)
        self.assertEqual(iface.write('/c/c2', '1'), None)

        ret = json.loads(iface.dump('/'))
        ret = json.dumps(ret, indent=4, sort_keys=True)

        self.assertEqual(val, ret)

        # cleanup
        self.assertEqual(iface.rm("/"), None)
        self.assertEqual(iface.dump('/'), '{}')

    def test_invdump(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')

        # cleanup
        self.assertEqual(iface.rm("/"), None)
        self.assertEqual(iface.dump('/doesnotexist'), 'null')

    def test_rm(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.write('/c/1', '1'), None)
        self.assertEqual(iface.exists('/c/1'), True)
        self.assertEqual(iface.rm('/c/1'), None)
        self.assertEqual(iface.exists('/c/1'), False)
        self.assertEqual(iface.exists('/c'), True)

        self.assertEqual(iface.write('/c2/1', '1'), None)
        self.assertEqual(iface.exists('/c2/1'), True)
        self.assertEqual(iface.rm('c2/1'), None)
        self.assertEqual(iface.exists('/c2/1'), False)
        self.assertEqual(iface.exists('/c2'), True)

        self.assertEqual(iface.write('/vm/uuid/test/key', 'val'), None)
        self.assertEqual(iface.exists('/vm/uuid/test/key'), True)
        self.assertEqual(iface.rm('/vm/uuid/test/key'), None)
        self.assertEqual(iface.exists('/vm/uuid/test/key'), False)
        self.assertEqual(iface.exists('/vm/uuid/test'), True)
        self.assertEqual(iface.rm('/vm'), None)
        self.assertEqual(iface.exists('/vm/uuid/test'), False)
        self.assertEqual(iface.exists('/vm/uuid'), False)
        self.assertEqual(iface.exists('/vm'), False)

        self.assertEqual(iface.write('/dom-store/uuid/test/key', 'val'), None)
        self.assertEqual(iface.write('/dom-store/uuid2/test/key', 'val'), None)
        self.assertEqual(iface.write('/dom-store/uuid3/test/key', 'val'), None)
        self.assertEqual(iface.exists('/dom-store/uuid/test/key'), True)
        self.assertEqual(iface.rm('/dom-store/uuid/test/key'), None)
        self.assertEqual(iface.exists('/dom-store/uuid/test/key'), False)
        self.assertEqual(iface.exists('/dom-store/uuid/test'), True)
        self.assertEqual(iface.exists('/dom-store/uuid/'), True)
        self.assertEqual(iface.rm('/dom-store/uuid'), None)
        self.assertEqual(iface.exists('/dom-store/uuid/'), False)
        self.assertEqual(iface.rm('/dom-store/'), None)
        self.assertEqual(iface.exists('/dom-store'), False)

        # cleanup
        self.assertEqual(iface.rm("/"), None)

    def test_invrm(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)
        self.assertEqual(iface.rm("/notvalid"), None)
        self.assertEqual(iface.rm("/not/valid"), None)
        self.assertEqual(iface.rm("/dom-store"), None)
        self.assertEqual(iface.rm("/dom-store/uuid"), None)
        self.assertEqual(iface.rm("/dom-store/uuid/xxx"), None)
        self.assertEqual(iface.rm("/vm"), None)
        self.assertEqual(iface.rm("/vm/uuid"), None)
        self.assertEqual(iface.rm("/vm/uuid/xxx"), None)

    def test_writes(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)

        tuples =  [("d0", "/d0", "d0val"),
                   ("d0x", "d0x", "d0xval"),
                   ("d1", "/d1/d1", "d1val"),
                   ("d1x", "d1x/d1x", "d1xval"),
                   ("d2", "/d2/d2/d2", "d2val"),
                   ("d3", "/d3/d3/d3/d3", "d3val"),
                   ("d4", "/d4/d4/d4/d4/d4", "d4val"),
                   ("vm", "/vm/uuid/foo", "vmval"),
                   ("vm", "vm/uuid2/foo/d2", "vmval2"),
                   ("dom-store", "/dom-store/uuid/foo", "dval"),
                   ("dom-store", "dom-store/uuid/foo", "dval2")]
        for root, key, val in tuples:
            # perform write
            self.assertEqual(iface.write(key, val), None)
            # cleanup
            self.assertEqual(iface.rm(root), None)
            self.assertEqual(iface.dump('/'), '{}')

    def test_inject(self):
        bus = dbus.SystemBus()
        dbd = bus.get_object('com.citrix.xenclient.db', '/')
        iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
        self.assertEqual(iface.rm("/"), None)
        service_ndvm = """
            {
              "uuid": "00000000-0000-0000-0000-000000000002",
              "type": "ndvm",
              "name": "Network2",
              "slot": "-1",
              "hidden": "false",
              "start_on_boot": "true",
              "start_on_boot_priority": "10",
              "provides-network-backend": "true",
              "provides-default-network-backend": "true",
              "shutdown-priority": "-15",
              "hidden-in-ui": "false",
              "measured": "false",
              "s3-mode": "restart",
              "domstore-read-access": "true",
              "domstore-write-access": "true",
              "image_path": "plugins/serviceimages/citrix.png",
              "icbinn-path": "\/config\/certs\/Network",
              "boot-sentinel": "booted",
              "v4v-firewall-rules": {
                "0": "myself -> 0:5555",
                "1": "0 -> myself:2222",
                "2": "myself -> 0:2222",
                "3": "myself:5555 -> 0",
                "4": "myself -> 0:4878"
              },
              "rpc-firewall-rules": {
                  "0": "allow destination org.freedesktop.DBus interface org.freedesktop.DBus",
                  "1": "allow destination com.citrix.xenclient.xenmgr interface org.freedesktop.DBus.Properties member Get",
                  "2": "allow destination com.citrix.xenclient.networkdaemon"
              },
              "policies": {
                "audio-access": "false",
                "audio-rec": "false",
                "cd-access": "false",
                "cd-rec": "false",
                "modify-vm-settings": "false"
              },
              "config": {
                "notify": "dbus",
                "debug": "true",
                "pae": "true",
                "acpi": "true",
                "hvm": "false",
                "apic": "true",
                "nx": "true",
                "v4v": "true",
                "memory": "176",
                "display": "none",
                "cmdline": "root=\/dev\/xvda1 iommu=soft xencons=hvc0",
                "kernel-extract": "\/boot\/vmlinuz",
                "flask-label": "system_u:system_r:ndvm_t",
                "pci": {
                  "0": {
                    "class": "0x0200",
                    "force-slot": "false"
                  },
                  "1": {
                    "class": "0x0280",
                    "force-slot": "false"
                  }
                },
                "disk": {
                  "0": {
                    "path": "\/storage\/ndvm\/ndvm.vhd",
                    "type": "vhd",
                    "mode": "r",
                    "shared": "true",
                    "device": "xvda1",
                    "devtype": "disk"
                  },
                  "1": {
                    "path": "\/storage\/ndvm\/ndvm-swap.vhd",
                    "type": "vhd",
                    "mode": "w",
                    "device": "xvda2",
                    "devtype": "disk"
                  }
                },
                "qemu-dm-path": ""
              }
            }
        """
        service_vm_obj = json.loads(service_ndvm)
        val = json.dumps(service_vm_obj, indent=4, sort_keys=True)

        iface.inject("/vm/somendvm", service_ndvm)

        ret = iface.dump("/vm/somendvm")
        ret = json.loads(ret)
        ret = json.dumps(ret, indent=4, sort_keys=True)

        # twiddle some bits
        service_vm_obj['uuid'] = "12345"
        service_vm_obj['config']['pae'] = "false"
        val = json.dumps(service_vm_obj, indent=4, sort_keys=True)
        iface.inject("/vm/somendvm", val)

        # validate twiddled bits
        ret = iface.dump("/vm/somendvm")
        ret = json.loads(ret)
        self.assertEqual(iface.read("/vm/somendvm/uuid"), "12345")
        self.assertEqual(iface.read("/vm/somendvm/config/pae"), "false")

        # validate whole thing
        ret = json.dumps(ret, indent=4, sort_keys=True)
        self.assertEqual(val, ret)

        # cleanup
        self.assertEqual(iface.rm("/"), None)
        self.assertEqual(iface.dump('/'), '{}')


def main():
    bus = dbus.SystemBus()
    dbd = bus.get_object('com.citrix.xenclient.db', '/')
    iface = dbus.Interface(dbd, 'com.citrix.xenclient.db')
    suite = unittest.TestLoader().loadTestsFromTestCase(TestDBD)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()
