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
    TODO: Write something here.
"""
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

    def __init__(self, vm_id, display_name=None, os_template=None,
                 memory_required=None, affinity_group=None,
                 instance_name=None):
        self.vm_id = vm_id
        self.display_name = display_name
        self.os_template = os_template
        self.instance_name = instance_name
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
    def is_full(self):
        return True if self.memory_free < (512*1024*1024) else False

    @property
    def occupancy_ratio(self):
        """ Returns the Windows virtual machines ratio of the host instance"""
        whole = self.memory_total
        part = self.memory_allocated
        try:
            ratio = float(part)/float(whole)
        except ZeroDivisionError:
            ratio = 0
        return round(ratio, 2)

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

    def win_ratio(self, filter_affinity=False):
        """ Returns the Windows virtual machines ratio of the host instance"""
        whole = self.amount_of_vms
        part = self.amount_of_windows_vms(filter_affinity)
        try:
            ratio = float(part)/float(whole)
        except ZeroDivisionError:
            ratio = 0
        return round(ratio, 2)

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
        """ Verifies if the host instance is dedicated.    
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

    def sort_windows_vms(self, reverse=False):
        result = list()
        for vm in sorted(filter(VM.is_windows, self.vms), reverse=reverse):
            result.append(vm)
        return result


class SegregationManager(object):

    def __init__(self, ias_handler=None, dry_run=False):
        self.ias_handler = ias_handler
        self.dry_run = bool(dry_run)

    @staticmethod
    def sort_by_resources(host_list, reverse=False):
        """ Sort a list of hosts starting with the lower occupancy ratio.
        """
        return sorted(host_list,
                      key=attrgetter('occupancy_ratio'),
                      reverse=reverse)

    @staticmethod
    def sort_by_windows_vms(host_list, reverse=False):
        """ Sort a list of hosts starting with the least amount of Windows 
        virtual machines. Dedicated hosts are ignored. Virtual Machines with
        anti-affinity rules are ignored.
        """
        result = list()

        # ignore dedicated hosts:
        for host in filter(lambda h: not h.is_dedicated(), host_list):
            # ignore anti-affinity virtual machines:
            if host.amount_of_windows_vms(filter_affinity=True) > 0:
                result.append(host)

        return sorted(result,
                      key=methodcaller('amount_of_windows_vms'),
                      reverse=reverse)

    def migrate_vm(self, vm, src_host, dst_host):
        """ Effectively migrates a virtual machine from a src_host to a 
        dst_host if src and dst are not the same. This method will use the 
        implementation for the proper IAS provider, passed as a parameter 
        during the initialization of this class. If dry_run is set to True,
        the migration will not take place.
    
        :param vm: a virtual machine to be migrated
        :type vm: VM
        :param src_host: source host the VM will be migrated from
        :type src_host: Host
        :param dst_host: destination host the VM will be migrated to
        :type dst_host: Host
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

        if dst_host.is_full:
            raise NotEnoughResources

        if dst_host.memory_free >= vm.memory_required:

            src_host.remove_vm(vm)
            dst_host.append_vm(vm)

            if self.dry_run:
                print("\t\t\t>>> Would migrate %s (%s) from %s to %s" %
                      (vm.display_name,
                       vm.os_template,
                       src_host.fqdn,
                       dst_host.fqdn))
            else:
                if self.ias_handler.migrate_vm(vm, src_host, dst_host):
                    print("\t\t\t>>> Migrated %s (%s) from %s to %s" %
                          (vm.display_name,
                           vm.os_template,
                           src_host.fqdn,
                           dst_host.fqdn))
                else:
                    print("\t\t\t>>> Error migrating %s (%s) from %s to %s" %
                          (vm.display_name,
                           vm.os_template,
                           src_host.fqdn,
                           dst_host.fqdn))

            return True
        else:
            raise NotEnoughResources

    def prepare_src_dst(self, min_win_vms, host_list):

        src_hosts = list()
        dst_hosts = list()

        for host in filter(lambda h: not h.is_dedicated(), host_list):

            if host.amount_of_windows_vms() == 0:
                pass
            elif 0 < host.amount_of_windows_vms() <= min_win_vms:
                src_hosts.append(host)
                continue
            else:
                dst_hosts.append(host)
                continue

        return {'src': src_hosts, 'dst': dst_hosts}

    def segregate(self, host_list, min_win_vms=5):

        hosts = self.prepare_src_dst(
            min_win_vms=min_win_vms,
            host_list=host_list
        )

        if len(hosts['dst']) == 0 and len(hosts['src']) == 0:
            print "Empty hypervisor!"
            return 0

        elif len(hosts['dst']) > 0 and len(hosts['src']) == 0:
            print "Healthy cluster!"
            return 0

        elif len(hosts['dst']) == 0 and len(hosts['src']) > 0:
            print "Bad situation, going recursive!"
            self.segregate(
                host_list=host_list,
                min_win_vms=min_win_vms-1
            )
            return 0

        else:

            print "Preparing migrations for hosts " \
                  "(minimum %s Windows VMs):\n" % min_win_vms

            for i in hosts['src']:
                print u'\u25b2' + " SRC: %s" % i.fqdn

            for i in hosts['dst']:
                print u'\u25bc' + " DST: %s" % i.fqdn
            print

        dst_hosts = self.sort_by_resources(hosts['dst'])
        src_hosts = self.sort_by_windows_vms(hosts['src'])

        for src in src_hosts:
            print "\tCurrent source: %s" % src.fqdn

            # only windows vms sorted by size, biggest first:
            for vm in sorted(filter(VM.is_windows, src.vms), reverse=True):
                print "\t\tCurrent VM: %s" % vm.instance_name

                try:
                    for dst in dst_hosts:
                        print "\t\t\tCurrent destination: %s" % dst.fqdn

                        try:
                            self.migrate_vm(vm=vm,
                                            src_host=src,
                                            dst_host=dst)
                            break
                        except NotEnoughResources:
                            print "\t\t\t\t(!) Not enough resources at %s" % dst.fqdn
                            continue

                except MigrateVMWithAffinity:
                    print "\t\t\t(!) Affinity configured for %s" % vm.instance_name
                    continue

    def migrate_linux_from_host(self, host, host_list):
        """ Move all linux virtual machines from Host with the most amount of
        Microsoft(R) Windows virtual machines.
        """

        sorted_windows_host_lst = self.sort_by_windows_vms(host_list, reverse=True)

        sorted_resources_host_lst = self.sort_by_resources(host_list)

        # gather all Linux VMs from the host with the biggest amount of Windows
        for vm in sorted(filter(lambda x: not VM.is_windows(x),
                                sorted_windows_host_lst[0].vms)):

            for dst_host in sorted_resources_host_lst:

                try:
                    # tries to migrate to the emptiest host
                    self.migrate_vm(vm=vm,
                                    dst_host=dst_host,
                                    src_host=sorted_windows_host_lst[0])
                    break

                except NotEnoughResources:
                    continue
                except SameSourceAndDestinationHost:
                    continue
                except MigrateVMWithAffinity:
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
        :return: The job ID for the async API call migrateVirtualMachine
        :rtype: str
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
    
        :param query: Supports all parameters from the listCluster API call
        :type query: str
        
        :return: List of clusters ID
        :rtype: list
        """
        result = list()

        cluster_list = self.listClusters(query)

        for cluster in cluster_list['cluster']:
            result.append(cluster['id'])

        return result

    def build_host_list(self, cluster_id):
        """ Builds a deque containing instances of Host from a given cluster, 
        each instance of Host contains a list of VM instances.
    
        :param cluster_id: CloudStack UUID for a specific cluster
        :type cluster_id: str
        
        :return: A deque of hosts, each with their respective virtual machines
        :rtype: deque
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

                    virtual_machine = VM(vm_id=vm['id'],
                                         display_name=vm['name'],
                                         os_template=vm['templatename'],
                                         affinity_group=vm['affinitygroup'],
                                         instance_name=vm['instancename'],
                                         memory_required=memory_bytes)

                    h.vms.append(virtual_machine)

            result.appendleft(h)

        return result

if __name__ == "__main__":
    pass
