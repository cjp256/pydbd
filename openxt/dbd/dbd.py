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

""" experimental dbd replacement """

import json
import gobject
import dbus
import dbus.service
import dbus.mainloop.glib
import atexit
import dpath.util
import dpath.exceptions
import logging as log
import logging.handlers
import argparse
import os
import threading
import re
import glob
import pyxs
import errno
import signal

class SimpleJsonDB(object):
    """ tracks a dict object and maintains an associated json database file """
    def __init__(self, file_path, virt_path, db_max_flush_delay, data):
        self.file_lock = threading.Lock()
        self.db_max_flush_delay = db_max_flush_delay
        self.data = data
        self.file_path = file_path
        self.virt_path = virt_path
        self.flush_timer = None
        self.flush_timer_lock = threading.Lock()
        self.db_read_from_disk()

    def db_read_from_disk(self):
        """ reads in json file and populates self.data """
        log.info('reading database = %s', self.file_path)

        self.file_lock.acquire()
        self.data.clear()
        rdata = {}

        try:
            rdata = json.loads(open(self.file_path, 'r').read())
        except IOError:
            log.info('unable to read db=%s, assuming empty', self.file_path)

        dpath.util.merge(self.data, rdata, flags=dpath.util.MERGE_REPLACE)

        self.file_lock.release()
        log.info('read database = %s', self.file_path)

    def db_write_to_disk(self):
        """ writes to json file with contents from self.data """
        log.debug('updating database = %s', self.file_path)

        # cancel outstanding timer, if any
        self.flush_timer_lock.acquire()
        if self.flush_timer:
            self.flush_timer.cancel()
        self.flush_timer = None
        self.flush_timer_lock.release()

        self.file_lock.acquire()
        data = self.data

        # if main db, shallow copy data and filter out vm and domstore nodes
        if self.file_path == '/config/db':
            data = data.copy()
            data.pop('vm', None)
            data.pop('dom-store', None)

        # delete empty db file
        if len(data) == 0:
            try:
                os.remove(self.file_path)
            except OSError:
                pass
            self.file_lock.release()
            log.info('removed database = %s', self.file_path)
        else:
            tmp_path = self.file_path + '.tmp'
            with open(tmp_path, 'w') as db_file:
                db_file.write(json.dumps(data, indent=4, sort_keys=True))
                db_file.flush()
                os.fsync(db_file.fileno())
                db_file.close()
            os.rename(tmp_path, self.file_path)
            self.file_lock.release()
            log.info('updated database = %s', self.file_path)

    def notify_data_changed(self):
        """ queue up a db flush when data has been modified """

        if self.db_max_flush_delay > 0.0:
            self.flush_timer_lock.acquire()
            if not self.flush_timer:
                self.flush_timer = threading.Timer(self.db_max_flush_delay,
                                                   self.db_write_to_disk)
                self.flush_timer.start()
                log.debug('db flush queued = %s', self.file_path)
            self.flush_timer_lock.release()
        else:
            log.debug('immediate flush = %s', self.file_path)
            self.db_write_to_disk()

class DBTree(object):
    """ maintains db tree and maintains associated SimpleJsonDB instances """
    def __init__(self, db_max_flush_delay):
        self.tree = {}
        self.linked_dbs = {}
        self.db_max_flush_delay = db_max_flush_delay
        self.main_db = SimpleJsonDB('/config/db', '',
                                    db_max_flush_delay, self.tree)
        self.db_tree_populate()

    @staticmethod
    def path_split(path):
        """ split up a path into a standardized array format """
        split = []

        # eliminate '' cells
        for elem in path.split('/'):
            if elem == '':
                continue
            split.append(elem)

        return split

    def get_parent_dict(self, split_path):
        """ get the parent dictionary for a path, returns None if not a dict """
        if len(split_path) == 0:
            return self.tree

        parent_split_path = split_path[:-1]
        obj = self.path_get(parent_split_path)

        # parent is not dictionary, return None
        if not isinstance(obj, dict):
            return None

        return obj

    def path_get(self, split_path, default=None):
        """ get the object for given path, returns default is does not exist """
        obj = self.tree

        if len(split_path) == 0:
            return obj

        for elem in split_path:
            obj = obj.get(elem, None)
            if obj == None:
                return default

        return obj

    def path_set(self, split_path, value, skip_db_lookup=False):
        """ set the object for given path, creating parents as required """
        if len(split_path) == 0:
            log.warning('ignoring write for invalid path')
            return None

        key = split_path[-1]
        parent_split_path = split_path[:-1]

        obj = self.tree
        if not skip_db_lookup:
            owner_db = self.db_lookup(split_path, create=True)

        # make tree as required
        for elem in parent_split_path:
            if obj.has_key(elem) == False:
                obj[elem] = {}
            obj = obj[elem]

        obj[key] = value

        if not skip_db_lookup:
            owner_db.notify_data_changed()
        return obj

    def path_rm(self, split_path):
        """ rm the object for given path """
        owner_db = self.db_lookup(split_path, create=False)
        if owner_db == None:
            return False

        log.debug("path_rm for split_path=%r", split_path)
        if len(split_path) == 0:
            log.debug("rm on root, clearing tree")
            self.tree.clear()
        else:
            parent_obj = self.get_parent_dict(split_path)
            if parent_obj == None:
                return False
            key = split_path[-1]
            log.debug("popping key=%s from parent=%r", key, parent_obj)
            if parent_obj.pop(key, None) == None:
                return False

        owner_db.notify_data_changed()

        # clear any linked children nodes, if any
        for child_db in self.db_list_children(split_path):
            log.debug("clearing child db=%s" % child_db.file_path)
            child_db.data.clear()
            self.db_unlink(child_db)

        return True

    def path_inject_json(self, split_path, json_string):
        """ inject/merge given json for given path """
        merge_data = json.loads(json_string)
        owner_db = self.db_lookup(split_path, create=True)
        target = self.path_get(split_path, default=None)
        if target == None:
            target = {}
            self.path_set(split_path, target)

        log.debug('merging to path=%r\n%r', split_path, merge_data)
        dpath.util.merge(target, merge_data, flags=dpath.util.MERGE_REPLACE)
        log.debug('merged to path=%r\n%r', split_path, merge_data)
        owner_db.notify_data_changed()

        # usage shouldn't go across db boundaries, but alert children to be safe
        for child_db in self.db_list_children(split_path):
            child_db.notify_data_changed()

    def db_list_children(self, split_path):
        """ get a list of all children dbs for given path """
        out = []
        virt_path = "/".join(split_path)
        for db_virt_path, db_obj in self.linked_dbs.iteritems():
            if db_virt_path.startswith(virt_path):
                out.append(db_obj)
                log.debug("add child=%r for split_path=%r", 
                          db_obj.virt_path, split_path)
        return out

    def db_link(self, db_type, db_path, db_name):
        """ link new or existing database to tree """
        log.info('linking type=%s path=%s name=%s', db_type, db_path, db_name)

        if db_type == 'vm' or db_type == 'dom-store':
            # original dbd just simply used the key name w/o restriction
            # as part of the file path name.  so we need to check input path 
            # for pathing traversal attacks
            if db_path != os.path.realpath(db_path):
                # all is not all that it appears to be
                log.error('invalid db_path: %r', db_path)
                return None

            new_dict = {}
            self.path_set([db_type, db_name], new_dict, skip_db_lookup=True)
            virt_path = "/".join([db_type, db_name])
            owner_db = SimpleJsonDB(db_path, virt_path,
                                    self.db_max_flush_delay, new_dict)
            self.linked_dbs[virt_path] = owner_db
        else:
            log.warning('db_link: invalid db type = %r', db_type)
        return owner_db

    def db_unlink(self, db_obj):
        """ unlink database from tree after flushing it """
        log.info('unlinking db = %s', db_obj.file_path)
        db_obj.db_write_to_disk()
        self.linked_dbs.pop(db_obj.virt_path)

    def db_lookup(self, split_path, create=False):
        """ find (and create if requested) db for given path """
        # short path must not be dom-store or vm, therefore main db
        if len(split_path) < 2:
            return self.main_db

        db_type = split_path[0]
        db_name = split_path[1]

        if db_type == 'dom-store' or db_type == 'vm':
            virt_path = "/".join([db_type, db_name])
            owner_db = self.linked_dbs.get(virt_path, None)
            if owner_db:
                return owner_db

            # db does not exist - bail if not creating
            if create == False:
                return None

            if db_type == 'dom-store':
                db_path = '/config/dom-store/' + db_name + '.db'
            if db_type == 'vm':
                db_path = '/config/vms/' + db_name + '.db'

            return self.db_link(db_type, db_path, db_name)

        # neither dom-store or vm, must be main db
        return self.main_db

    def db_tree_populate(self):
        """ populate tree from existing datbase (initialization only) """
        # make sure db dirs exists for first boot
        for path in ['/config/vms', '/config/dom-store']:
            try:
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise

        for db_path in glob.glob('/config/dom-store/*.db'):
            db_name = re.sub(r'^/config/dom-store/', '', db_path)
            db_name = re.sub(r'.db$', '', db_name)
            self.db_link('dom-store', db_path, db_name)

        for db_path in glob.glob('/config/vms/*.db'):
            db_name = re.sub(r'^/config/vms/', '', db_path)
            db_name = re.sub(r'.db$', '', db_name)
            self.db_link('vm', db_path, db_name)

    def db_tree_flush(self):
        """ immediately flush all linked dbs to disk """
        log.debug('db_tree_flush = %r', self.linked_dbs.keys())
        log.debug('flushing db=%s...', self.main_db.file_path)
        self.main_db.db_write_to_disk()
        log.debug('flushed db=%s...', self.main_db.file_path)
        for child_db in self.linked_dbs.values():
            log.debug('flushing db=%s...', child_db.file_path)
            child_db.db_write_to_disk()
            log.debug('flushed db=%s...', child_db.file_path)

class DBDService(dbus.service.Object):
    """ provides dbd's dbus service interfaces """
    # pylint: disable=interface-not-implemented
    def __init__(self, db_max_flush_delay, lookup_sender):
        bus_name = dbus.service.BusName('com.citrix.xenclient.db',
                                        bus=dbus.SystemBus())
        dbus.service.Object.__init__(self, bus_name, '/')

        self.lookup_sender = lookup_sender
        self.system_bus = dbus.SystemBus()
        self.dbus = self.system_bus.get_object('org.freedesktop.DBus',
                                               '/org/freedesktop/DBus')
        self.dbus_iface = dbus.Interface(self.dbus, 'org.freedesktop.DBus')
        self.xenstore = pyxs.xs()
        self.db_tree = DBTree(db_max_flush_delay)

    def cleanup(self):
        """ on exit, flush db tree """
        log.info('exiting - flushing tree...')
        self.db_tree.db_tree_flush()

    def get_uuid_from_domid(self, domid):
        """ get uuid from specified domid using xenstore """
        vm_path = self.xenstore.read(0, '/local/domain/' + str(domid) + '/vm')
        log.debug('vm_path = %r for domid = %r', vm_path, domid)
        # The UUID is actually in the vm_path, but this is the old way...
        uuid = self.xenstore.read(0, vm_path + '/uuid')
        log.debug('uuid = %r for domid = %r', uuid, domid)
        return uuid

    def get_sender_domid(self, sender):
        """ get sender's domain id """
        domid = self.dbus_iface.GetConnectionDOMID(sender)
        log.debug('sender = %r - domid = %r', sender, domid)
        return int(domid)

    def sender_path_split(self, sender, path):
        """ return standardized split path given the sender """
        split = DBTree.path_split(path)
        if self.lookup_sender == False:
            return split

        domid = self.get_sender_domid(sender)
        if domid == 0:
            return split

        uuid = self.get_uuid_from_domid(domid)
        split.insert(0, uuid)
        split.insert(0, 'dom-store')
        return split

    ############################################################
    # com.citrix.xenclient.db.read
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='s',
                         sender_keyword='sender')
    def read(self, path, sender):
        """ read a key, returning empty string if key is invalid """
        log.debug('read path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        value = self.db_tree.path_get(sender_path_split)

        # only string values are OK, otherwise return empty string
        if isinstance(value, basestring):
            return value

        return ''

    ############################################################
    # com.citrix.xenclient.db.read_binary - NOT SUPPORTED
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='ay',
                         sender_keyword='sender')
    def read_binary(self, path, sender):
        """ unsupported, no users? if so, they should base64 encode """
        log.error('read_binary path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        log.error('returning garbage for path=%r', sender_path_split)
        return ['not', 'supported']

    ############################################################
    # com.citrix.xenclient.db.write
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='ss',
                         out_signature='',
                         sender_keyword='sender')
    def write(self, path, value, sender):
        """ write a string value to given path """
        log.debug('write path=%s value=%s sender=%r', path, value, sender)
        sender_path_split = self.sender_path_split(sender, path)
        current_value = self.db_tree.path_get(sender_path_split)

        # do not write if target path is dict
        if isinstance(current_value, dict):
            log.warning('ignoring write to dict path = %r', sender_path_split)
        else:
            self.db_tree.path_set(sender_path_split, str(value))

    ############################################################
    # com.citrix.xenclient.db.inject
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='ss',
                         out_signature='',
                         sender_keyword='sender')
    def inject(self, path, value, sender):
        """ inject/merge json value to given path """
        log.debug('inject path=%s value=%r sender=%r', path, value, sender)
        sender_path_split = self.sender_path_split(sender, path)
        self.db_tree.path_inject_json(sender_path_split, value)

    ############################################################
    # com.citrix.xenclient.db.dump
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='s',
                         sender_keyword='sender')
    def dump(self, path, sender):
        """ dump json string for object at given path """
        log.debug('dump path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        current_value = self.db_tree.path_get(sender_path_split)
        if current_value == None:
            return 'null'
        return json.dumps(current_value, indent=4, sort_keys=True)

    ############################################################
    # com.citrix.xenclient.db.list
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='as',
                         sender_keyword='sender')
    def list(self, path, sender):
        """ list all nodes for a given path, if object is dict """
        log.debug('list path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        current_value = self.db_tree.path_get(sender_path_split, default={})
        if isinstance(current_value, dict):
            return current_value.keys()
        return []

    ############################################################
    # com.citrix.xenclient.db.rm
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='',
                         sender_keyword='sender')
    def rm(self, path, sender):
        """ rm object at given path """
        # pylint: disable=invalid-name
        log.debug('rm path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        self.db_tree.path_rm(sender_path_split)

    ############################################################
    # com.citrix.xenclient.db.exists
    ############################################################
    @dbus.service.method(dbus_interface='com.citrix.xenclient.db',
                         in_signature='s',
                         out_signature='b',
                         sender_keyword='sender')
    def exists(self, path, sender):
        """ checks whether a path exists (of any type) """
        log.debug('exists path=%s sender=%r', path, sender)
        sender_path_split = self.sender_path_split(sender, path)
        current_value = self.db_tree.path_get(sender_path_split)
        if current_value == None:
            return False
        return True

def main():
    """ main entry point """
    parser = argparse.ArgumentParser()

    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.add_argument('--no-verbose', dest='verbose', action='store_false')
    parser.set_defaults(verbose=False)

    parser.add_argument('--lookup-sender', dest='lookup', action='store_true')
    parser.add_argument('--no-lookup-sender', dest='lookup',
                        action='store_false')
    parser.set_defaults(lookup=True)

    parser.add_argument('--syslog', dest='syslog', action='store_true')
    parser.add_argument('--no-syslog', dest='syslog', action='store_false')
    parser.set_defaults(syslog=False)

    parser.add_argument('--max-db-flush-delay',
                        help='max time to flush db after write',
                        type=float)
    parser.set_defaults(db_max_flush_delay=3.0)

    args = parser.parse_args()

    log_level = log.INFO
    if args.verbose:
        log_level = log.DEBUG

    log.basicConfig(format='[dbd.%(levelname)s %(asctime)s] %(message)s',
                    level=log_level)

    if args.syslog:
        syslog_handler = logging.handlers.SysLogHandler(
            address='/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_DAEMON)
        syslog_handler.setLevel(log_level)
        syslog_formatter = logging.Formatter('[dbd.%(levelname)s] %(message)s')
        syslog_handler.setFormatter(syslog_formatter)
        log.getLogger('').handlers = []
        log.getLogger('').addHandler(syslog_handler)

    log.info('db_max_flush_delay = %r', args.db_max_flush_delay)
    log.info('verbose = %r', args.verbose)
    log.info('syslog = %r', args.syslog)
    log.info('lookup_sender = %r', args.lookup)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    dbus.mainloop.glib.threads_init()
    gobject.threads_init()

    dbd_service = DBDService(args.db_max_flush_delay, args.lookup)
    def cleanup():
        """ exit handler """
        log.info("caught signal, cleaning up")
        dbd_service.cleanup()
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log.debug('entering main loop...')
    loop = gobject.MainLoop()
    loop.run()

if __name__ == '__main__':
    main()
