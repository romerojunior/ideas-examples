#!/usr/bin/env python
# -*- coding:utf8 -*-

#      Copyright 2017, Schuberg Philis BV
#
#      Licensed to the Apache Software Foundation (ASF) under one
#      or more contributor license agreements.  See the NOTICE file
#      distributed with this work for additional information
#      regarding copyright ownership.  The ASF licenses this file
#      to you under the Apache License, Version 2.0 (the
#      "License"); you may not use this file except in compliance
#      with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#      Unless required by applicable law or agreed to in writing,
#      software distributed under the License is distributed on an
#      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#      KIND, either express or implied.  See the License for the
#      specific language governing permissions and limitations
#      under the License.

#      Romero Galiza Jr. - rgaliza@schubergphilis.com

"""
This module was designed to segregate Microsoft(R) Windows from Linux virtual
machines within a group of hosts (Cosmic or Cloudstack), thus helping reducing
the amount of licenses needed for all Microsoft(R) Windows hosts.
The Implementation is based on a ranking algorithm: a rank of most empty hosts
and a rank of greatest amount of Microsoft(R) Windows virtual machines. 
"""

from operator import attrgetter
from collections import deque

UNIX = 'LinuxVM'
WIN = 'WindowsVM'


class DestinationHostFull(Exception):
    """Raised if the destination host doesn't have enough capacity"""
    pass


class SameSourceAndDestinationHost(Exception):
    """Raised if the destination host and source host are the same device"""
    pass


class VM(object):
    def __init__(self, vm_id, os_type):
        self.vm_id = vm_id
        self.os_type = os_type

    @property
    def capacity_required(self):
        """The amount of capacity required in a host to allocated this VM"""
        return 1


class Host(object):
    def __init__(self, host_id):
        self.host_id = host_id
        self.vms = list()
        self.capacity_total = 10

    def __eq__(self, other):
        """Method to compare instances of hosts by their hostname"""
        return self.host_id == other.host_id

    def __lt__(self, other):
        """Method to handle sorting of hosts instances by available capacity"""
        return self.capacity_available < other.capacity_available

    @property
    def capacity_available(self):
        return self.capacity_total - len(self.vms)

    @property
    def amount_of_windows_vms(self):
        counter = 0
        for vm in self.vms:
            if vm.os_type == WIN:
                counter += 1
        return counter


def most_empty_stack(host_list):
    """ Compare all hosts within a list of hosts and returns a sorted list, the
    first element being the host with the most amount of available capacity.

    :param host_list: list containing all hosts to analyze
    :return: list with sorted hosts, hosts with the emptiest space comes first
    :rtype: deque
    """
    return deque(sorted(host_list, reverse=True))


def most_windows_stack(host_list, filter_full=True):
    """ Compare all hosts within a list of hosts and returns a sorted list, the
    first element being the host with the greatest amount of Microsoft(R) 
    Windows virtual machines. Hosts without any capacity to allocate more
    virtual machines will be ignored if :param filter_full is set to True.

    :param host_list: list containing all hosts to analyze
    :param filter_full: if set to True full hosts will be ignored
    :return: list with sorted hosts, hosts with greatest amount of Microsoft(R)
     Windows virtual machines comes first
    :rtype: deque
    """

    _most_win = deque()

    for _host in host_list:
        if not _host.capacity_available <= 0:
            _most_win.append(_host)

    if filter_full:
        return sorted(_most_win,
                      key=attrgetter('amount_of_windows_vms'),
                      reverse=True)
    else:
        return deque(sorted(host_list,
                            key=attrgetter('amount_of_windows_vms'),
                            reverse=True))


def least_windows_stack(host_list):
    """ Compare all hosts within a list of hosts and returns a sorted list, the
    first element being the host with the least amount of Microsoft(R) Windows 
    virtual machines. Hosts without any Microsoft(R) Windows virtual machines
    will be ignored.

    :param host_list: list containing all hosts to analyze
    :return: list with sorted hosts, hosts with greatest amount of Microsoft(R)
     Windows virtual machines comes first
    :rtype: deque
    """

    _least_win = deque()

    for _host in host_list:
        if _host.amount_of_windows_vms > 0:
            _least_win.append(_host)

    return sorted(_least_win, key=attrgetter('amount_of_windows_vms'))


def migrate_vm(vm, src_host, dst_host):
    """ Effectively migrates a virtual machine from a src_host to a dst_host if
    src and dst are not the same.

    :param vm: a virtual machine to be migrated
    :param src_host: source host the virtual machine will be migrated from
    :param dst_host: destination host the virtual machine will be migrated to
    :return: True if the virtual machine has been migrated or False otherwise
    :rtype: bool
    """
    if src_host == dst_host:
        # migration is not needed nor possible
        # add warn log message
        raise SameSourceAndDestinationHost
    if dst_host.capacity_available >= vm.capacity_required:
        # migrates virtual machine, implementation based on cosmic API
        # eventually this needs to be inside a try-except block
        src_host.vms.remove(vm)
        dst_host.vms.append(vm)
        # adds info log msg (slack?) if migration actually happens
        print("\t\t\tM > Migrated %s from %s to %s" % (vm.vm_id,
                                                       src_host.host_id,
                                                       dst_host.host_id))
        return True
    else:
        # adds warn log msg
        raise DestinationHostFull


def is_linux(vm):
    """ Verifies if the OS type for a given virtual machine is Linux. Useful as
    a filter.

    :param vm: a virtual machine to be analyzed
    :return: True if the virtual machine OS type is Linux-like, False otherwise
    :rtype: bool
    """
    return True if vm.os_type == UNIX else False


def is_windows(vm):
    """ Verifies if the OS type for a given virtual machine is Windows. Useful 
    as a filter.

    :param vm: a virtual machine to be analyzed
    :return: True if the virtual machine OS type is Linux-like, False otherwise
    :rtype: bool
    """
    return True if vm.os_type == WIN else False


host0 = Host('host0')
host1 = Host('host1')
host2 = Host('host2')
host3 = Host('host3')
host4 = Host('host4')

host0.vms.append(VM('vm-1', WIN))
host0.vms.append(VM('vm-2', UNIX))
host0.vms.append(VM('vm-3', UNIX))
host0.vms.append(VM('vm-4', UNIX))
host0.vms.append(VM('vm-5', UNIX))
host0.vms.append(VM('vm-6', UNIX))

host1.vms.append(VM('vm-7', WIN))
host1.vms.append(VM('vm-8', WIN))
host1.vms.append(VM('vm-9', UNIX))
host1.vms.append(VM('vm-10', UNIX))
host1.vms.append(VM('vm-11', UNIX))
host1.vms.append(VM('vm-12', UNIX))

host2.vms.append(VM('vm-13', WIN))
host2.vms.append(VM('vm-14', WIN))
host2.vms.append(VM('vm-15', WIN))
host2.vms.append(VM('vm-16', UNIX))
host2.vms.append(VM('vm-17', UNIX))
host2.vms.append(VM('vm-18', UNIX))

host3.vms.append(VM('vm-19', WIN))
host3.vms.append(VM('vm-20', WIN))
host3.vms.append(VM('vm-21', WIN))
host3.vms.append(VM('vm-22', WIN))
host3.vms.append(VM('vm-23', UNIX))
host3.vms.append(VM('vm-24', UNIX))

host4.vms.append(VM('vm-25', WIN))
host4.vms.append(VM('vm-26', WIN))
host4.vms.append(VM('vm-27', WIN))
host4.vms.append(VM('vm-28', WIN))
host4.vms.append(VM('vm-29', WIN))
host4.vms.append(VM('vm-30', UNIX))


cluster = [host0, host1, host2, host3, host4]

print "\n"


for i in range(50):

    most_windows_host_lst = most_windows_stack(cluster)
    most_empty_host_lst = most_empty_stack(cluster)
    least_windows_host_lst = least_windows_stack(cluster)

    print "\n"
    print "\t%s) Most Windows: %s" % (i, most_windows_host_lst[0].host_id)
    print "\t%s) Least Windows: %s" % (i, least_windows_host_lst[0].host_id)
    print "\t%s) Most Empty: %s" % (i, most_empty_host_lst[0].host_id)

    # migrating linux vms from most windows most to emptiest host:
    for linux_vm in filter(is_linux, most_windows_host_lst[0].vms):

        try:
            migrate_vm(vm=linux_vm,
                       src_host=most_windows_host_lst[0],
                       dst_host=most_empty_host_lst[0])
            break
        except SameSourceAndDestinationHost:
            continue
        except DestinationHostFull:
            continue

    # migrating windows vms from least windows hosts to most windows host:
    for windows_vm in filter(is_windows, least_windows_host_lst[0].vms):

        try:
            migrate_vm(vm=windows_vm,
                       src_host=least_windows_host_lst[0],
                       dst_host=most_windows_host_lst[0])
            break
        except SameSourceAndDestinationHost:
            continue
        except DestinationHostFull:
            continue

    print
    for host in cluster:
        for vm in host.vms:
            print host.host_id, vm.vm_id, vm.os_type
        print

    print "-----------------------------------"

