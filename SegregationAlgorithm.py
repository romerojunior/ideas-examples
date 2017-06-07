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
the amount of licenses needed for all Microsoft(R) Windows hosts. The implemen-
tation is based on a ranking algorithms. 

Import considerations:

    * Each [FULL] host will ignored from iterations (no resources available);
    * Each virtual machine with a defined affinity group won't be migrated;
      By default the VM property `has_affinity` is set to False.    

Example:
    
    4 hosts cluster:
    
    Mc: Host with the greatest amount of Microsoft(R) Windows virtual machines
    Lc: Host with the least amount of Microsoft(R) Windows virtual machines
    Ec: Host with the largest amount of unallocated resources
    W:  Microsoft(R) Windows virtual machine
    L:  Linux virtual machine
    -:  Unallocated resource
      
          ___Host0___ ___Host1___ ___Host2___ ___Host3___
         |   -  W    |        L  |  L     -  |  L   L    |
         |  W      - | W  -      |     W     |    L   L  |
INIT     |    W  L   |     W  -  | W  -    - |      -    |
         |  -        | -     -   |       -   |   W    -  |
         |___________|___________|___________|___________|
              |           |                       | 
             Mc          Ec                      Lc
    
          Loop:
              0) Define Mc, Ec, Lc
              1) Moves first possible L from Mc to Ec
              2) Moves first possible W from Lc to Mc

           ___Host0___ ___Host1___ ___Host2___ ___Host3___
          |   -  W    |        L  |  L     -  |  L   L    |
          |  W      - | W  L      |     W     |    L   L  |
1st LOOP  |    W  -   |     W  -  | W  -    - |      -    |
          |  W        | -     -   |       -   |   -    -  |
          |___________|___________|___________|___________|
               |            |           |
               Mc          Lc           Ec

           ___Host0___ ___Host1___ ___Host2___ ___Host3___
          |   W  W    |        L  |  L     -  |  L   L    |
          |  W      - | -  L      |     W     |    L   L  |
2nd LOOP  |    W  -   |     W  -  | W  -    - |      -    |
          |  W        | -     -   |       -   |   -    -  |
          |___________|___________|___________|___________|
               |          |  |
               Mc        Lc  Ec

           ___Host0___ ___Host1___ ___Host2___ ___Host3___
          |   W  W    |        L  |  L     -  |  L   L    |
          |  W      - | -  L      |     W     |    L   L  |
3rd LOOP  |    W  W   |     -  -  | W  -    - |      -    |
          |  W        | -     -   |       -   |   -    -  |
          |___________|___________|___________|___________|
               |           |            |
               Mc          Ec          Lc

           ___Host0___ ___Host1___ ___Host2___ ___Host3___
          |   W  W    |        L  |  L     -  |  L   L    |
          |  W      W | -  L      |     W     |    L   L  |
4th LOOP  |    W  W   |     -  -  | -  -    - |      -    |
          |  W        | -     -   |       -   |   -    -  |
          |___________|___________|___________|___________|
               |           |            |
               Mc          Ec          Lc

           __[FULL]___ ___Host1___ ___Host2___ ___Host3___
          |   W  W    |        L  |  L     -  |  L   L    |
          |  W      W | -  L      |     W     |    L   L  |
5th LOOP  |    W  W   |     -  -  | -  -    - |      -    |
          |  W        | -     -   |       -   |   -    -  |
          |___________|___________|___________|___________|
                            |         |    |
                           Ec        Lc   Mc                Lc == Mc -> END.

"""

from operator import attrgetter
from collections import deque

LINUX = 'LinuxVM'
WIN = 'WindowsVM'


class InvalidHostList(Exception):
    """Raised if the segregation algorithm receives an invalid list of hosts"""
    def __init__(self):
        msg = "Cannot handle an invalid list of hosts."
        Exception.__init__(self, msg)
    pass


class DestinationHostFull(Exception):
    """Raised if the destination host doesn't have enough capacity"""
    def __init__(self):
        msg = "The destination host is full."
        Exception.__init__(self, msg)
    pass


class SameSourceAndDestinationHost(Exception):
    """Raised if the destination host and source host are the same device"""
    def __init__(self):
        msg = "Migration to and from the same host is not possible."
        Exception.__init__(self, msg)
    pass


class MigrateVMWithAffinity(Exception):
    """Raised if virtual machine belong to an affinity group"""
    def __init__(self):
        msg = "Virtual machines with affinity group won't be migrated."
        Exception.__init__(self, msg)
    pass


class VM(object):
    def __init__(self, vm_id, os_type):
        self.vm_id = vm_id
        self.os_type = os_type

    @property
    def capacity_required(self):
        """The amount of capacity required in a host to allocated this VM"""
        return 1

    @property
    def has_affinity(self):
        """Check if the virtual machine belongs to any affinity rule"""
        return False


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
    if vm.has_affinity:
        # migration not needed when affinity group is set
        raise MigrateVMWithAffinity
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
        print("\t\tM > Migrated %s (%s) from %s to %s" % (vm.vm_id,
                                                          vm.os_type,
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
    return True if vm.os_type == LINUX else False


def is_windows(vm):
    """ Verifies if the OS type for a given virtual machine is Windows. Useful 
    as a filter.

    :param vm: a virtual machine to be analyzed
    :return: True if the virtual machine OS type is Linux-like, False otherwise
    :rtype: bool
    """
    return True if vm.os_type == WIN else False


def segregate_cluster(host_list):
    """ Main algorithm (procedure) for segregating virtual machines, refer to 
    docstring at the beginning of this module for detailed information.

    :param host_list: an arbitrary list of `Host` instances
    """

    # checks if the list of hosts is valid and iterable:
    for _host in host_list:
        if not isinstance(_host, Host):
            raise InvalidHostList

    iterate = True

    while iterate:

        most_windows_host_lst = most_windows_stack(host_list)
        most_empty_host_lst = most_empty_stack(host_list)
        least_windows_host_lst = least_windows_stack(host_list)

        # migrates the first possible Linux virtual machine from the host with
        # the greatest amount of Microsoft(R) Windows virtual machines to the
        # host with the largest amount of unallocated resources.
        for linux_vm in filter(is_linux, most_windows_host_lst[0].vms):

            try:
                migrate_vm(vm=linux_vm,
                           src_host=most_windows_host_lst[0],
                           dst_host=most_empty_host_lst[0])
                break
            except MigrateVMWithAffinity:
                continue
            except SameSourceAndDestinationHost:
                continue
            except DestinationHostFull:
                continue

        # migrates the first possible Microsoft(R) Windows virtual machine from
        # the host with the least amount of Microsoft(R) Windows virtual
        # machines to the host with the greatest amount of Microsoft(R) Windows
        # virtual machines.
        for windows_vm in filter(is_windows, least_windows_host_lst[0].vms):

            try:
                migrate_vm(vm=windows_vm,
                           src_host=least_windows_host_lst[0],
                           dst_host=most_windows_host_lst[0])
                break
            except MigrateVMWithAffinity:
                continue
            except SameSourceAndDestinationHost:
                iterate = False
                continue
            except DestinationHostFull:
                continue


if __name__ == "__main__":

    # mocking:

    host0 = Host('host0')
    host1 = Host('host1')
    host2 = Host('host2')
    host3 = Host('host3')
    host4 = Host('host4')
    host5 = Host('host5')
    host6 = Host('host6')
    host7 = Host('host7')

    host0.vms.append(VM('vm-1', WIN))
    host0.vms.append(VM('vm-2', LINUX))
    host0.vms.append(VM('vm-3', LINUX))
    host0.vms.append(VM('vm-4', LINUX))
    host0.vms.append(VM('vm-5', LINUX))
    host0.vms.append(VM('vm-6', WIN))
    host0.vms.append(VM('vm-7', LINUX))
    host0.vms.append(VM('vm-8', WIN))
    host0.vms.append(VM('vm-9', WIN))

    host1.vms.append(VM('vm-10', WIN))
    host1.vms.append(VM('vm-11', WIN))
    host1.vms.append(VM('vm-12', LINUX))
    host1.vms.append(VM('vm-13', LINUX))
    host1.vms.append(VM('vm-14', WIN))
    host1.vms.append(VM('vm-15', LINUX))
    host1.vms.append(VM('vm-16', LINUX))
    host1.vms.append(VM('vm-17', WIN))

    host2.vms.append(VM('vm-18', WIN))
    host2.vms.append(VM('vm-19', WIN))
    host2.vms.append(VM('vm-20', WIN))
    host2.vms.append(VM('vm-21', LINUX))
    host2.vms.append(VM('vm-22', LINUX))
    host2.vms.append(VM('vm-23', LINUX))

    host3.vms.append(VM('vm-24', WIN))
    host3.vms.append(VM('vm-25', WIN))
    host3.vms.append(VM('vm-26', WIN))
    host3.vms.append(VM('vm-27', WIN))
    host3.vms.append(VM('vm-28', LINUX))
    host3.vms.append(VM('vm-29', LINUX))
    host3.vms.append(VM('vm-30', WIN))
    host3.vms.append(VM('vm-31', LINUX))

    host4.vms.append(VM('vm-32', WIN))
    host4.vms.append(VM('vm-33', WIN))
    host4.vms.append(VM('vm-34', WIN))
    host4.vms.append(VM('vm-35', WIN))
    host4.vms.append(VM('vm-36', WIN))
    host4.vms.append(VM('vm-37', LINUX))
    host4.vms.append(VM('vm-38', WIN))
    host4.vms.append(VM('vm-39', LINUX))

    host5.vms.append(VM('vm-40', WIN))
    host5.vms.append(VM('vm-41', LINUX))
    host5.vms.append(VM('vm-42', LINUX))
    host5.vms.append(VM('vm-43', WIN))
    host5.vms.append(VM('vm-44', WIN))
    host5.vms.append(VM('vm-45', LINUX))
    host5.vms.append(VM('vm-46', WIN))
    host5.vms.append(VM('vm-47', LINUX))

    host6.vms.append(VM('vm-48', LINUX))
    host6.vms.append(VM('vm-49', WIN))
    host6.vms.append(VM('vm-50', LINUX))
    host6.vms.append(VM('vm-51', WIN))
    host6.vms.append(VM('vm-52', LINUX))
    host6.vms.append(VM('vm-53', LINUX))
    host6.vms.append(VM('vm-54', WIN))
    host6.vms.append(VM('vm-55', LINUX))

    host7.vms.append(VM('vm-56', WIN))
    host7.vms.append(VM('vm-57', LINUX))
    host7.vms.append(VM('vm-58', WIN))
    host7.vms.append(VM('vm-59', LINUX))
    host7.vms.append(VM('vm-60', WIN))
    host7.vms.append(VM('vm-61', LINUX))
    host7.vms.append(VM('vm-62', WIN))
    host7.vms.append(VM('vm-63', LINUX))

    cluster = [host0, host1, host2, host3, host4, host5, host6, host7]

    segregate_cluster(host_list=cluster)

    print
    for host in cluster:
        for virtual_machine in host.vms:
            print host.host_id, virtual_machine.vm_id, virtual_machine.os_type
        print
