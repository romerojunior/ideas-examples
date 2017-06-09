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

    * Each dedicated host will be ignored;
    * Each host without enough resources will be ignored;
    * Each virtual machine with a defined affinity group won't be migrated;
    * Each virtual machine with a defined affinity group will be ignored from
      the `Lc` (least amount of Microsoft(R) Windows) calculation.

Example:
    
    4 hosts cluster without any affinity group applied:
    
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

from collections import deque
from operator import methodcaller, attrgetter


class OsType(object):
    """This class contains the definition of all possible template types"""

    # todo: read different OS types from config file instead of cls attributes

    LINUX = ['linux', 'debian', 'ubuntu']
    WIN = ['windows', 'microsoft']


class InvalidHostList(Exception):
    """Raised if the segregation algorithm receives an invalid list of hosts"""
    def __init__(self):
        msg = "Cannot handle an invalid list of hosts."
        Exception.__init__(self, msg)
    pass


class NotEnoughResources(Exception):
    """Raised if the destination host doesn't have enough resources"""
    def __init__(self):
        msg = "The destination host doesn't have enough resources."
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
    def __init__(self, vm_id, vm_name=None, os_type=None, memory_required=None,
                 affinity_group=None):
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.os_type = os_type
        self.memory_required = memory_required
        self.affinity_group = affinity_group

    @property
    def has_affinity(self):
        """Check if the virtual machine belongs to any affinity rule.
        
        :return: True if an affinity group is set, False otherwise.
        :rtype: bool
        """
        return bool(self.affinity_group)


class Host(object):
    def __init__(self, host_id, host_name=None, memory_total=None,
                 memory_used=None, memory_allocated=None, dedicated=False):
        self.host_id = host_id
        self.host_name = host_name
        self.vms = list()
        self.memory_total = memory_total
        self.memory_used = memory_used
        self.memory_allocated = memory_allocated
        self.dedicated = dedicated

    def __eq__(self, other):
        """Method to compare instances of hosts by their hostname"""
        return self.host_id == other.host_id

    def __lt__(self, other):
        """Method to handle sorting of hosts instances by available memory"""
        return self.memory_free < other.memory_free

    @property
    def memory_free(self):
        """Property to define the amount of available memory"""
        return self.memory_total - self.memory_allocated

    def amount_of_windows_vms(self, filter_affinity=False):
        """Property to define the amount of Microsoft(R) Windows machines 
        running in the instance of Host, filtering virtual machines with
        affinity group if flagged to do so."""
        counter = 0
        for vm in filter(is_windows, self.vms):
            if filter_affinity:
                if not vm.has_affinity:
                    counter += 1
            else:
                counter += 1
        return counter


def most_empty_stack(host_list):
    """ Compare all hosts within a list of hosts and returns a sorted list, the
    first element being the host with the most amount of available capacity.

    :param host_list: list containing all hosts to analyze
    :return: list with sorted hosts, hosts with the emptiest space comes first
    :rtype: deque
    """

    _most_empty = deque()

    for _host in filter(lambda h: not is_dedicated(h), host_list):
        _most_empty.append(_host)

    return sorted(host_list, key=attrgetter('memory_free'), reverse=True)


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

    for _host in filter(lambda h: not is_dedicated(h), host_list):
        if not _host.memory_free <= 0:
            _most_win.append(_host)

    if filter_full:
        return sorted(_most_win,
                      key=methodcaller('amount_of_windows_vms'),
                      reverse=True)
    else:
        return deque(sorted(host_list,
                            key=methodcaller('amount_of_windows_vms'),
                            reverse=True))


def least_windows_stack(host_list):
    """ Compare all hosts within a list of hosts and returns a sorted list, the
    first element being the host with the least amount of Microsoft(R) Windows 
    virtual machines. Hosts without any Microsoft(R) Windows virtual machines
    will be ignored. Microsoft(R) Windows virtual machines with affinity group
    won't be taken into account since they can't be migrated.

    :param host_list: list containing all hosts to analyze
    :return: list with sorted hosts, hosts with greatest amount of Microsoft(R)
     Windows virtual machines comes first
    :rtype: deque
    """

    _least_win = deque()

    for _host in filter(lambda h: not is_dedicated(h), host_list):
        if _host.amount_of_windows_vms(filter_affinity=True) > 0:
            _least_win.append(_host)

    return sorted(_least_win, key=methodcaller('amount_of_windows_vms', True))


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
    if dst_host.memory_free >= vm.memory_required:
        # migrates virtual machine, implementation based on cosmic API
        # eventually this needs to be inside a try-except block
        src_host.vms.remove(vm)
        dst_host.vms.append(vm)
        # adds info log msg (slack?) if migration actually happens
        print("\t\tM > Migrated %s (%s) from %s to %s" % (vm.vm_name,
                                                          vm.os_type,
                                                          src_host.host_name,
                                                          dst_host.host_name))
        return True
    else:
        # adds warn log msg
        raise NotEnoughResources


def is_dedicated(host):
    """ Verifies if the instance of Host is dedicated. Useful as a filter.

    :param host: a virtual machine to be analyzed
    :return: True if instance is dedicated, False otherwise
    :rtype: bool
    """
    return True if host.dedicated else False


def is_linux(vm):
    """ Verifies if the OS type for a given virtual machine is Linux. Useful as
    a filter.

    :param vm: a virtual machine to be analyzed
    :return: True if the virtual machine OS type is Linux-like, False otherwise
    :rtype: bool
    """
    return True if vm.os_type in OsType.LINUX else False


def is_windows(vm):
    """ Verifies if the OS type for a given virtual machine is Windows. Useful 
    as a filter.

    :param vm: a virtual machine to be analyzed
    :return: True if the virtual machine OS type is Linux-like, False otherwise
    :rtype: bool
    """
    return True if vm.os_type in OsType.WIN else False


def segregate_cluster(host_list):
    """ Main algorithm (procedure) for segregating virtual machines, refer to 
    docstring at the beginning of this module for detailed information.

    :param host_list: an arbitrary list of `Host` instances
    """

    # checks if the list of hosts is valid:
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
            except NotEnoughResources:
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
            except NotEnoughResources:
                continue


if __name__ == "__main__":
    pass
