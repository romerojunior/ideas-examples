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

from collections import deque
from operator import methodcaller, attrgetter
from time import sleep
import hashlib
import hmac
import base64
import urllib
import json


class FilteredDomain(Exception):
    """Raised if a virtual machine being migrated should be filtered"""
    def __init__(self):
        msg = "Won't migrate filtered virtual machines."
        Exception.__init__(self, msg)
    pass


class DedicatedHostAsDestination(Exception):
    """Raised if a virtual machine tries to be migrated to a dedicated host"""
    def __init__(self):
        msg = "Cannot migrate a virtual machine to a dedicated host."
        Exception.__init__(self, msg)
    pass


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
        msg = "Destination host not suitable due to affinity rules."
        Exception.__init__(self, msg)
    pass


class VM(object):

    def __init__(self, vm_id, display_name=None, os_template=None,
                 memory_required=None, affinity_group=None,
                 instance_name=None, domain=None):
        self.vm_id = vm_id
        self.display_name = display_name
        self.os_template = os_template
        self.instance_name = instance_name
        self.memory_required = memory_required
        self.affinity_group = affinity_group
        self.domain = domain

    def __lt__(self, other):
        """ Method to handle sorting of VM instances by the amount of memory.
        
        :return:               comparison between the current VM instance and 
                               another VM instance
        :rtype:                bool
        
        """
        return self.memory_required < other.memory_required

    @property
    def has_affinity(self):
        """Check if the virtual machine belongs to any affinity rule.
        
        :return:               True if an affinity group is set or False 
                               otherwise
        :rtype:                bool
        """
        return bool(self.affinity_group)

    @staticmethod
    def is_windows(vm):
        """ Verifies if the OS template for a given VM is Microsoft(R) Windows. 
        This static method is particularly useful as a filter. A lambda 
        function can be used to invert the result finding only linux VMs.
    
        :param vm:             VM instance to be verified
        :type vm:              VM
        :return:               True if the VM OS type is from Windows type or 
                               False otherwise
        :rtype:                bool
        """
        return True if vm.os_template.lower().startswith('win') else False


class Host(object):

    def __init__(self, host_id, fqdn=None, memory_total=None,
                 memory_used=None, memory_allocated=None, dedicated=False,
                 ip_address=None):
        self.host_id = host_id
        self.fqdn = fqdn
        self.vms = list()
        self.memory_total = memory_total
        self.memory_used = memory_used
        self.memory_allocated = memory_allocated
        self.dedicated = dedicated
        self.ip_address = ip_address
        self.migrations_in = 0
        self.migrations_out = 0

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
        """ Returns the amount of virtual machines running on the host 
        instance.
        """
        return len(self.vms)

    @property
    def occupancy_ratio(self):
        """ Returns the host instance occupancy ratio, which is the rounded 
        quotient of the total memory and allocated memory of a Host instance.
        
        :return:               anything between 0 and 1
        :rtype:                float
        """
        whole = self.memory_total
        part = self.memory_allocated
        try:
            ratio = float(part)/float(whole)
        except ZeroDivisionError:
            ratio = 0
        return round(ratio, 2)

    def append_vm(self, vm):
        """ Appends a virtual machine to a host instance, update its
        resources and migration counter.
    
        :param vm:             Instance of VM
        :type vm:              VM
        """
        self.migrations_in += 1
        self.memory_allocated += vm.memory_required
        self.vms.append(vm)
        return

    def remove_vm(self, vm):
        """ Removes a virtual machine from a host instance, update its
        resources and migration counter.
    
        :param vm:             Instance of VM
        :type vm:              VM
        """
        self.migrations_out += 1
        self.memory_allocated -= vm.memory_required
        self.vms.remove(vm)
        return

    def amount_of_windows_vms(self, filter_affinity=False):
        """ Returns the amount of  Windows virtual machines running in a host 
        instance, filtering virtual machines with affinity group is possible.
        
        :param filter_affinity: filter virtual machines with affinity
        :return:                windows virtual machines count
        :rtype:                 int
        """
        counter = 0
        for vm in filter(VM.is_windows, self.vms):
            if filter_affinity:
                if not vm.has_affinity:
                    counter += 1
            else:
                counter += 1
        return counter

    def win_ratio(self, filter_affinity=False):
        """ Returns the host instance Windows virtual machines ratio.
        
        :param filter_affinity: filter virtual machines with affinity
        :return:                anything between 0 and 1
        :rtype:                 float
        """
        whole = self.amount_of_vms
        part = self.amount_of_windows_vms(filter_affinity)
        try:
            ratio = float(part)/float(whole)
        except ZeroDivisionError:
            ratio = 0
        return round(ratio, 2)

    def amount_of_affinity_vms(self):
        """ Counts the amount of virtual machines within the host instance 
        with anti-affinity group configured.

        :return:               amount of virtual machines with affinity
        :rtype:                int
        """
        return len(
            [vm for vm in self.vms if vm.has_affinity]
        )

    def is_dedicated(self):
        """ Verifies if the host instance is dedicated. Although each instance
        has a dedicated attribute, a method can be used as a filter function.
        
        :return:               True if instance is dedicated, False otherwise
        :rtype:                bool
        """
        return True if self.dedicated else False

    def sort_windows_vms(self, reverse=False):
        """ Returns a list of Windows virtual machines sorted by memory.
        
        :param reverse:        reverses the sort order
        :type reverse:         bool
        :return:               list of virtual machine instances
        :rtype:                list
        """
        return sorted(
            [vm for vm in self.vms if VM.is_windows(vm)],
            reverse=reverse
        )

    def affinity_group_list(self):
        """ Returns a list with all affinity group ID from virtual machines
         within the host instance.
        
        :return:                list with affinity group ids (str)
        :rtype:                 list
        """
        result = list()
        for vm in self.vms:
            if vm.has_affinity:
                result.append(str(vm.affinity_group))
        return list(set(result))


class MigrationState(object):

    SUCCESS = 37
    AVOIDED = 94
    FAILURE = 31
    WARNING = 33


class SegregationManager(object):

    def __init__(self, ias_handler=None, max_occupancy=0.9, dry_run=True):
        self.ias_handler = ias_handler
        self.dry_run = bool(dry_run)
        self.filtered_domains = list()
        self.max_occupancy = max_occupancy

    @staticmethod
    def sort_by_resources(host_list, reverse=False):
        """ Sort a list of hosts starting with the host with lower occupancy
        ratio, unless reversed.
        
        :param host_list:      list of hosts instances
        :type host_list:       list
        :param reverse:        reverse sorting
        :type reverse:         bool
        :rtype:                list
        """
        return sorted(host_list,
                      key=attrgetter('occupancy_ratio'),
                      reverse=reverse)

    @staticmethod
    def sort_by_windows_vms(host_list, reverse=False):
        """ Sort a list of hosts starting with the least amount of Windows 
        virtual machines. Dedicated hosts are ignored.

        :param host_list:     list of hosts instances
        :type host_list:      list
        :param reverse:       reverse sorting
        :type reverse:        bool
        :rtype:               list
        """
        result = list()

        # ignore dedicated hosts:
        for host in filter(lambda h: not h.is_dedicated(), host_list):
            result.append(host)

        return sorted(result,
                      key=methodcaller('amount_of_windows_vms'),
                      reverse=reverse)

    def filter_domains(self, *uuid):

        for e in uuid:
            self.filtered_domains.append(e)

    def migrate_vm(self, vm, src_host, dst_host):
        """ Effectively migrates a virtual machine from a src_host to a 
        dst_host. This method will use a given IAS provider implementation for
        for a migration call. If dry_run is set to True, the migration will not
        happen, but you will be notified of what would have happened.
    
        :param vm:             virtual machine instance
        :type vm:              VM
        :param src_host:       source host instance
        :type src_host:        Host
        :param dst_host:       destination host instance
        :type dst_host:        Host
        :return:               True if VM has been migrated, False otherwise
        :rtype:                bool
        """

        if vm.domain in self.filtered_domains:
            self.print_migration(
                MigrationState.AVOIDED,
                'Filtered', vm, src_host, dst_host
            )
            raise FilteredDomain

        if dst_host.is_dedicated():
            raise DedicatedHostAsDestination

        if src_host == dst_host:
            raise SameSourceAndDestinationHost

        if dst_host.occupancy_ratio >= self.max_occupancy:
            raise NotEnoughResources

        if vm.has_affinity:
            if vm.affinity_group in dst_host.affinity_group_list():
                self.print_migration(
                    MigrationState.WARNING,
                    'Affinity detected', vm, src_host, dst_host
                )
                raise MigrateVMWithAffinity

        if dst_host.memory_free >= vm.memory_required:

            src_host.remove_vm(vm)
            dst_host.append_vm(vm)

            if self.dry_run:
                self.print_migration(
                    MigrationState.SUCCESS,
                    'Would migrate', vm, src_host, dst_host
                )
            else:
                if self.ias_handler.migrate_vm(vm, src_host, dst_host):
                    self.print_migration(
                        MigrationState.SUCCESS,
                        'Migrated', vm, src_host, dst_host
                    )
                else:
                    # error occurred, give vm back to source host:
                    dst_host.remove_vm(vm)
                    src_host.append_vm(vm)

                    self.print_migration(
                        MigrationState.FAILURE,
                        'Error migrating', vm, src_host, dst_host
                    )

            return True
        else:
            raise NotEnoughResources

    def migrate_linux_from_host(self, src_host, host_list):
        """ Move all linux virtual machines from source host with the most 
        amount of Microsoft Windows virtual machines to the most resourceful
        host within a host list.
        
        :param src_host:       source host instance
        :type src_host:        Host
        :param host_list:      list of host instances
        :type host_list:       list
        """
        sorted_host_list = self.sort_by_resources(host_list)

        for vm in sorted(
                filter(
                    lambda x: not VM.is_windows(x), src_host.vms
                ),
                reverse=True
        ):
            try:
                for dst_host in sorted_host_list:
                    try:
                        self.migrate_vm(vm=vm,
                                        dst_host=dst_host,
                                        src_host=src_host)
                        break
                    except NotEnoughResources:
                        continue
                    except SameSourceAndDestinationHost:
                        continue
                    except DedicatedHostAsDestination:
                        continue
                    except MigrateVMWithAffinity:
                        continue
            except FilteredDomain:
                continue

    def migrate_windows_to_host(self, dst_host, host_list):
        """ Move all windows virtual machines from host list to a destination
        host instance until resources are exhausted.
        
        :param dst_host:       destination host instance
        :type dst_host:        Host
        :param host_list:      list of host instances
        :type host_list:       list
        """
        for src_host in host_list:
            try:
                for vm in sorted(
                    filter(
                        lambda x: VM.is_windows(x), src_host.vms
                    )
                ):
                    try:
                        self.migrate_vm(vm=vm,
                                        dst_host=dst_host,
                                        src_host=src_host)
                    except MigrateVMWithAffinity:
                        continue
                    except FilteredDomain:
                        continue
            except SameSourceAndDestinationHost:
                continue
            except NotEnoughResources:
                break
        return

    def segregate(self, host_list):
        """ Hard segregation works by moving away all the Linux virtual
        machine from the pivot, which is the host with the greatest amount of
        Windows virtual machines, and then moving Windows virtual machines to
        it, until it reaches max_occupancy. This process is done for each host
        instance within host_list recursively.
        
        :param host_list:      list of host instances
        :type host_list:       list
        """
        win_counter = 0

        for h in host_list:
            for vm in h.vms:
                if VM.is_windows(vm):
                    win_counter += 1

        # do not continue if no more Windows virtual machines are present:
        if win_counter == 0:
            print "Finished."
            return

        sorted_host_list = self.sort_by_windows_vms(
            host_list=host_list,
            reverse=True
        )

        pivot = sorted_host_list[0]
        remaining_hosts = sorted_host_list[1:]

        print "Current host: %s" % pivot.fqdn
        print "\tMigrating Linux virtual machines away from %s" % \
            pivot.fqdn.split('.')[0]

        self.migrate_linux_from_host(
            src_host=pivot,
            host_list=host_list
        )

        print "\tMigrating Windows virtual machines to %s" % \
            pivot.fqdn.split('.')[0]

        self.migrate_windows_to_host(
            dst_host=pivot,
            host_list=host_list
        )

        try:
            self.segregate(remaining_hosts)
        except IndexError:
            print "No more iterations possible for this cluster."

    def print_migration(self, state, msg, vm, src_host, dst_host):
        """ Print a standard output line for each migration based on its state.
        
        :param state:          attribute from class MigrationState
        :type state:           int
        :param msg:            message to be displayed
        :type msg:             str
        :param vm:             virtual machine
        :type vm:              VM
        :param src_host:       source host
        :type src_host:        Host
        :param dst_host:       destination host
        :type dst_host:        Host
        """
        # output format states:
        f = '\033[0;%sm{0:>26} {1:>18} ' \
            '| {2:<40} {3} -> {4} ({5})\033[0m' % state

        # truncating long strings:
        template = (vm.os_template[:37] + "...") \
            if len(vm.os_template) > 40 else vm.os_template

        print(f.format(msg + ":",
                       vm.instance_name,
                       template,
                       src_host.fqdn.split('.')[0],
                       dst_host.fqdn.split('.')[0],
                       dst_host.occupancy_ratio))


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
        """ Cloudstack/Cosmic asynchronous API call to migrateVirtualMachine,
        waits until the job is finished.

        :type vm:              VM
        :param vm:             virtual machine to be migrated
        :type dst_host:        Host
        :param dst_host:       destination host for the migration
        :type src_host:        source host for the migration
        :param src_host:       Host
        :return:               true if successfully migrated or false otherwise
        :rtype:                bool
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

    def build_cluster_list(self, **query):
        """ Builds a list with all clusters ID available under the CloudStack
        instance.
    
        :param query:          Supports all parameters from the listCluster
        :type query:           str
        :return:               list of clusters ID
        :rtype:                list
        """
        result = list()

        cluster_list = self.listClusters(query)

        for cluster in cluster_list['cluster']:
            result.append(cluster['id'])

        return result

    def build_host_list(self, cluster_id):
        """ Builds a deque containing instances of Host from a given cluster, 
        each instance of Host contains a list of VM instances.
    
        :param cluster_id:     CloudStack UUID for a specific cluster
        :type cluster_id:      str
        :return:               a list of host instances
        :rtype:                list
        """
        result = deque()

        host_list = self.listHosts({'clusterid': cluster_id})

        for host in host_list['host']:

            is_dedicated = self.listDedicatedHosts({'hostid': host['id'],
                                                    'listall': 'true'})

            h = Host(host_id=host['id'],
                     fqdn=host['name'],
                     memory_allocated=host['memoryallocated'],
                     memory_total=host['memorytotal'],
                     memory_used=host['memoryused'],
                     ip_address=host['ipaddress'],
                     dedicated=(True if is_dedicated else False))

            vm_list = self.listVirtualMachines({'hostid': h.host_id,
                                                'listall': 'true'})
            if vm_list:

                for vm in vm_list['virtualmachine']:

                    memory_bytes = int(vm['memory'])*1024*1024

                    affinity_group = vm['affinitygroup'][0]['id'] \
                        if vm['affinitygroup'] else None

                    virtual_machine = VM(vm_id=vm['id'],
                                         display_name=vm['name'],
                                         os_template=vm['templatename'],
                                         affinity_group=affinity_group,
                                         instance_name=vm['instancename'],
                                         memory_required=memory_bytes,
                                         domain=vm['domain'])

                    h.vms.append(virtual_machine)

            result.appendleft(h)

        return list(result)

if __name__ == "__main__":
    pass
