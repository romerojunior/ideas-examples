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

from copy import copy
from collections import deque
from operator import methodcaller, attrgetter
from time import sleep
import hashlib
import hmac
import base64
import urllib
import json


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

    def __init__(self, vm_id, vm_name=None, os_template=None,
                 memory_required=None, affinity_group=None):
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.os_template = os_template
        self.memory_required = memory_required
        self.affinity_group = affinity_group

    def __lt__(self, other):
        """Method to handle sorting of VM instances by the amount of memory"""
        return self.memory_required < other.memory_required

    @property
    def has_affinity(self):
        """Check if the virtual machine belongs to any affinity rule.
        
        :return: True if an affinity group is set, False otherwise.
        :rtype: bool
        """
        return bool(self.affinity_group)

    @staticmethod
    def is_windows(vm):
        """ Verifies if the OS template for a given VM is Microsoft(R) Windows. 
        This static method is particularly useful as a filter. A lambda 
        function can be used to invert the result finding only linux VMs.
    
        :param vm: Virtual machine to verify
        :type vm: VM
        :return: True if the VM OS type is from Microsoft (R) Windows type, 
         False otherwise
        :rtype: bool
        """
        return True if vm.os_template.lower().startswith('win') else False


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

    @property
    def amount_of_vms(self):
        """Property to define the amount of virtual machines"""
        return len(self.vms)

    @property
    def is_full(self):
        if self.memory_free > (512*1024*1024):
            return False
        else:
            return True

    def append_vm(self, vm):
        """ Appends a virtual machine to a host taking into account the amount
        of resources required for such.
    
        :param vm: Instance of VM
        :type vm: VM
        """
        self.memory_allocated += vm.memory_required
        self.vms.append(vm)
        return

    def remove_vm(self, vm):
        """ Removes a virtual machine to a host taking into account the amount
        of resources required for such.
    
        :param vm: Instance of VM
        :type vm: VM
        """
        self.memory_allocated -= vm.memory_required
        self.vms.remove(vm)
        return

    def amount_of_windows_vms(self, filter_affinity=False):
        """ Method to define the amount of Microsoft(R) Windows machines 
        running in the instance of Host, filtering virtual machines with
        affinity group if flagged to do so."""
        counter = 0
        for vm in filter(VM.is_windows, self.vms):
            if filter_affinity:
                if not vm.has_affinity:
                    counter += 1
            else:
                counter += 1
        return counter

    def amount_of_affinity_vms(self):
        """ Counts the amount of virtual machines with affinity group.

        :return: Counter with the amount of VMs with affinity group set
        :rtype: int
        """
        counter = 0
        for vm in self.vms:
            if vm.has_affinity:
                counter += 1
        return counter

    def is_dedicated(self):
        """ Verifies if the instance of Host is dedicated. Useful as a filter.
    
        :return: True if instance is dedicated, False otherwise
        :rtype: bool
        """
        return True if self.dedicated else False

    def is_empty(self):
        """ Verifies if the host is empty.

        :return: True host is empty, otherwise False.
        :rtype: bool
        """
        return True if self.vms else False


class SegregationManager(object):

    def __init__(self, ias_handler=None, dry_run=False):
        self.ias_handler = ias_handler
        self.dry_run = bool(dry_run)
        # minimum amount of memory per host before considering it full (bytes):
        self.min_memory_per_host = 8*1024*1024*1024

    def most_empty_stack(self, host_list):
        """ Compare all hosts within a list of hosts and returns a sorted list, 
        the first element being the host with the highest amount of resources
        available, if the amount of available memory is the same, the tie 
        breaker will be amount of running virtual machines.
    
        :param host_list: list containing all hosts to analyze
        :type host_list: deque
        :return: list with sorted hosts, hosts with the highest amount of
         resources available comes first
        :rtype: deque
        """

        tmp_a = list()
        tmp_b = list()
        result = list()

        for i in host_list:
            for n in host_list:
                if n == i:
                    tmp_b.append(n)
                    tmp_a = sorted(tmp_b,
                                   key=attrgetter('memory_free'),
                                   reverse=True)
                else:
                    if n.memory_free == i.memory_free:
                        tmp_b.append(n)
                    tmp_a = sorted(tmp_b,
                                   key=attrgetter('amount_of_vms'))

        for i in tmp_a:
            if i not in result:
                result.append(i)

        return result

    def most_windows_stack(self, host_list, filter_full=True):
        """ Compare all hosts within a list of hosts and returns a sorted list,
        the first element being the host with the greatest amount of Microsoft
        Windows VMs. Hosts without any capacity to allocate more VMs will be 
        ignored if :param filter_full is set to True.
    
        :param host_list: list containing all hosts to analyze
        :type host_list: deque
        :param filter_full: if set to True full hosts will be ignored
        :type filter_full: bool
        :return: list with sorted hosts, hosts with greatest amount of 
        Microsoft(R) Windows VM comes first
        :rtype: deque
        """

        most_win_dq = deque()

        for host in filter(lambda h: not h.is_dedicated(), host_list):
            # only non-dedicated hosts
            if host.memory_free >= self.min_memory_per_host:
                # only hosts with enough memory
                most_win_dq.append(host)

        if filter_full:
            # by default returns only hosts with enough memory
            return sorted(most_win_dq,
                          key=methodcaller('amount_of_windows_vms'),
                          reverse=True)
        else:
            return deque(sorted(host_list,
                                key=methodcaller('amount_of_windows_vms'),
                                reverse=True))

    def least_windows_stack(self, host_list):
        """ Compare all hosts within a list of hosts and returns a sorted list, 
        the first element being the host with the least amount of Microsoft(R) 
        Windows virtual machines. Hosts without any Microsoft(R) Windows VM 
        will be ignored. Microsoft(R) Windows virtual machines with affinity 
        group won't be taken into account since they can't be migrated.
    
        :param host_list: list containing all hosts to analyze
        :type host_list: deque
        :return: list with sorted hosts, hosts with greatest amount of 
        Microsoft(R) Windows virtual machines comes first
        :rtype: deque
        """

        least_win_dq = deque()

        for host in filter(lambda h: not h.is_dedicated(), host_list):
            # only non-dedicated hosts
            if host.amount_of_windows_vms(filter_affinity=True) > 0:
                # only non-affinity windows vms are counted
                least_win_dq.append(host)

        return sorted(least_win_dq,
                      key=methodcaller('amount_of_windows_vms', True))

    def migrate_vm(self, vm, src_host, dst_host):
        """ Effectively migrates a virtual machine from a src_host to a 
        dst_host if src and dst are not the same. This method will use the 
        implementation for the proper IAS provider, passed as a parameter 
        during the initialization of this class. If dry_run is set to True,
        the migration will not take place.
    
        :param vm: a virtual machine to be migrated
        :param src_host: source host the VM will be migrated from
        :param dst_host: destination host the VM will be migrated to
        :return: True if the VM has been migrated or False otherwise
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

            src_host.remove_vm(vm)
            dst_host.append_vm(vm)

            if self.dry_run:
                print("\t\t>>> Would migrate %s (%s) from %s to %s" %
                      (vm.vm_name,
                       vm.os_template,
                       src_host.host_name,
                       dst_host.host_name))
            else:
                if self.ias_handler.migrate_vm(vm, src_host, dst_host):
                    print("\t\t>>> Migrated %s (%s) from %s to %s" %
                          (vm.vm_name,
                           vm.os_template,
                           src_host.host_name,
                           dst_host.host_name))
                else:
                    print("\t\t>>> Error migrating %s (%s) from %s to %s" %
                          (vm.vm_name,
                           vm.os_template,
                           src_host.host_name,
                           dst_host.host_name))

            return True
        else:
            print "\t\t[DEBUG] - VM: %s \t MEM_REQ: %sMB \t HOST_FREE_MEM: %sMB \t HOST: %s" % (
                vm.vm_name, vm.memory_required/1024/1024, dst_host.memory_free/1024/1024, dst_host.host_name
            )
            raise NotEnoughResources

    def prepare_emptiest_host(self, host_list):
        """testing new algorithm"""

        most_empty_host_lst = self.most_empty_stack(host_list)

        # gather linux vm from the most empty host:
        for vm in sorted(filter(lambda x: not VM.is_windows(x),
                         most_empty_host_lst[0].vms)):

            for dst_host in most_empty_host_lst[1:]:
                try:
                    # tries to migrate to the 2nd emptiest host
                    self.migrate_vm(vm=vm,
                                    dst_host=dst_host,
                                    src_host=most_empty_host_lst[0])
                    break

                except NotEnoughResources:
                    print "foo"
                    # goes to the next emptiest host (3rd, 4th, etc)
                    continue

        print "\t[DEBUG] Emptiest host is now ready (%s)!" \
              % most_empty_host_lst[0].host_name

    def magic(self, host_list):
        """testing new algorithm"""

        hl_cp = copy(host_list)

        self.prepare_emptiest_host(hl_cp)

        emptiest_host = self.most_empty_stack(hl_cp)[0]
        remaining_hosts = self.most_empty_stack(hl_cp)[1:]

        for src_host in self.least_windows_stack(remaining_hosts):
            # get smallest vms from remaining least windows hosts:
            for vm in sorted(filter(VM.is_windows, src_host.vms)):
                try:
                    self.migrate_vm(vm=vm,
                                    src_host=src_host,
                                    dst_host=emptiest_host)
                    continue
                except MigrateVMWithAffinity:
                    # affinity! go to the next vm
                    continue
                except NotEnoughResources:
                    try:
                        hl_cp.remove(emptiest_host)
                    except ValueError:
                        return
                    self.magic(hl_cp)
                    pass

    def segregate_cluster(self, host_list):
        """ Main algorithm (procedure) for segregating virtual machines, refer 
        to docstring at the beginning of this module for detailed information.
    
        :param host_list: an arbitrary list of `Host` instances
        :type host_list: deque
        """

        # checks if the list of hosts is valid:
        for host in host_list:
            if not isinstance(host, Host):
                raise InvalidHostList

        iterate = True

        while iterate:

            most_windows_host_lst = self.most_windows_stack(host_list)
            most_empty_host_lst = self.most_empty_stack(host_list)

            # migrates the first possible Linux virtual machine from the host
            # with the greatest amount of Microsoft(R) Windows virtual machines
            # to the host with the largest amount of unallocated resources.
            for linux_vm in filter(lambda vm: not VM.is_windows(vm),
                                   most_windows_host_lst[0].vms):
                try:
                    self.migrate_vm(vm=linux_vm,
                                    src_host=most_windows_host_lst[0],
                                    dst_host=most_empty_host_lst[0])
                    break
                except MigrateVMWithAffinity:
                    print "\t[DEBUG] - A - MigrateVMWithAffinity"
                    continue
                except SameSourceAndDestinationHost:
                    print "\t[DEBUG] - A - SameSourceAndDestinationHost"
                    continue
                except NotEnoughResources:
                    print "\t[DEBUG] - A - NotEnoughResources"
                    continue

            least_windows_host_lst = self.least_windows_stack(host_list)

            # migrates the smallest Microsoft(R) Windows virtual machine
            # from the host with the least amount of Microsoft(R) Windows
            # virtual machines to the host with the greatest amount of
            # Microsoft(R) Windows virtual machines.
            for windows_vm in sorted(filter(VM.is_windows,
                                     least_windows_host_lst[0].vms)):

                for most_windows_host in most_windows_host_lst:

                    try:
                        self.migrate_vm(vm=windows_vm,
                                        src_host=least_windows_host_lst[0],
                                        dst_host=most_windows_host)
                        break
                    except MigrateVMWithAffinity:
                        print "\t[DEBUG] - B - MigrateVMWithAffinity"
                        break
                    except SameSourceAndDestinationHost:
                        print "\t[DEBUG] - B - SameSourceAndDestinationHost"
                        iterate = False
                        break
                    except NotEnoughResources:
                        print "\t[DEBUG] - B - NotEnoughResources"
                        continue


class SignedAPICall(object):

    def __init__(self, api_url, api_key, secret):
        self.api_url = api_url
        self.api_key = api_key
        self.secret = secret
        self.params = None

    def request(self, args):
        args['apiKey'] = self.api_key

        self.params = list()
        self._sort_request(args)
        self._create_signature()
        self._build_post_request()

    def _sort_request(self, args):
        keys = sorted(args.keys())

        for key in keys:
            self.params.append(key + '=' + urllib.quote_plus(args[key]))

    def _create_signature(self):
        self.query = '&'.join(self.params)
        digest = hmac.new(
            self.secret,
            msg=self.query.lower(),
            digestmod=hashlib.sha1).digest()

        self.signature = base64.b64encode(digest)

    def _build_post_request(self):
        self.query += '&signature=' + urllib.quote_plus(self.signature)
        self.value = self.api_url + '?' + self.query


class CloudStack(SignedAPICall):
    """
    Every Cloudstack API request has the format: 
    Base URL + API Path + Command String + Signature
    """
    def __getattr__(self, name):
        def handler_function(*args, **kwargs):
            if kwargs:
                return self._make_request(name, kwargs)
            return self._make_request(name, args[0])
        return handler_function

    def _http_get(self, url):
        response = urllib.urlopen(url)
        return response.read()

    def _make_request(self, command, args):
        args['response'] = 'json'
        args['command'] = command
        self.request(args)
        data = self._http_get(self.value)
        key = command.lower() + "response"
        return json.loads(data)[key]

    def migrate_vm(self, vm, src_host, dst_host):
        """ Main algorithm (procedure) for segregating virtual machines, refer 
        to docstring at the beginning of this module for detailed information.

        :type vm: VM
        :param vm: Virtual Machine to be migrated
        :type src_host: Host
        :param src_host: Source host in which the virtual machine is running
        :type dst_host: Host
        :param dst_host: Destination host for the virtual machine migration
        :return The job ID for the async API call migrateVirtualMachine
        :rtype str
        """
        request = {'virtualmachineid': vm.vm_id, 'hostid': dst_host.host_id}

        # start async api call:
        result = self.migrateVirtualMachine(request)

        async_job = {'jobid': result['jobid']}

        while True:
            result_async = self.queryAsyncJobResult(async_job)
            # 0 - pending; 1 - success; 2 - error

            if result_async['jobstatus'] == 0:
                sleep(3)
            elif result_async['jobstatus'] == 1:
                return True
            elif result_async['jobstatus'] == 2:
                return False

    def gather_host_list(self, cluster_id):
        """ Main algorithm (procedure) for segregating virtual machines, refer 
        to docstring at the beginning of this module for detailed information.
    
        :param cluster_id: CloudStack UUID for a specific cluster
        :type cluster_id: str
        :return A deque of hosts, each with their respective virtual machines
        :rtype deque
        """
        result = deque()

        host_list = self.listHosts({'clusterid': cluster_id})

        for host in host_list['host']:

            is_dedicated = self.listDedicatedHosts({'hostid': host['id'],
                                                    'listall': 'true'})

            h = Host(host_id=host['id'],
                     host_name=host['name'],
                     memory_allocated=host['memoryallocated'],
                     memory_total=host['memorytotal'],
                     memory_used=host['memoryused'],
                     dedicated=(True if is_dedicated else False))

            vm_list = self.listVirtualMachines({'hostid': h.host_id,
                                                'listall': 'true'})
            if vm_list:

                for vm in vm_list['virtualmachine']:

                    memory_bytes = int(vm['memory'])*1024*1024

                    virtual_machine = VM(vm_id=vm['id'],
                                         vm_name=vm['name'],
                                         os_template=vm['templatename'],
                                         affinity_group=vm['affinitygroup'],
                                         memory_required=memory_bytes)

                    h.vms.append(virtual_machine)

            result.appendleft(h)

        return result


if __name__ == "__main__":
    pass
