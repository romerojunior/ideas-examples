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
Example:
    qemu = QemuGuestAgentAPI('10.0.0.1', 'i-10-1010-VM')    
    print qemu.guest_network_get_interfaces
    
Reference:
    http://wiki.qemu.org/Features/GuestAgent
"""
import paramiko
from paramiko.ssh_exception import SSHException


class QemuGuestAgentAPI(object):

    def __init__(self, host_ipaddr, instance_name):
        self.host_ipaddr = host_ipaddr
        self.instance_name = instance_name

    def __getattr__(self, attr):

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.host_ipaddr, allow_agent=True)
        except SSHException:
            exit(1)

        query = "'{ \"execute\": \"%s\" }'" % attr.replace("_", "-")

        command = "virsh qemu-agent-command %s %s" % (self.guest.instance_name,
                                                      query)

        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.readlines()[0]

        ssh.close()

        return output

if __name__ == "__main__":
    pass
