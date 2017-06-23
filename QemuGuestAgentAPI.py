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
import json
import paramiko
from paramiko.ssh_exception import SSHException


class ConnectionManager(object):

    def __init__(self, ip_addr, port=22, timeout=60):
        self.ip_addr = ip_addr
        self.port = port
        self.ssh = paramiko.SSHClient()
        self.timeout = timeout

    def _connect(self):
        """ Internal method - Tries to connect to the SSHClient() instance.
        
        :return True in case the connection is successful, False otherwise
        :rtype bool
        """

        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.ssh.connect(hostname=self.ip_addr,
                             port=self.port,
                             allow_agent=True)
        except SSHException:
            return False

        return True

    def _execute(self, cmd):
        """ Internal method - Executes a command (string) and returns its 
        stdin, stdout and stderr as a tuple.
        
        :param cmd: Command to execute on a remote host
        :type cmd: str
        :return: Tuple containing stdin, stdout and stderr
        :rtype: tuple
        """

        try:
            stdin, stdout, stderr = self.ssh.exec_command(command=cmd,
                                                          timeout=self.timeout)
            return stdin, stdout, stderr
        except SSHException:
            return None, None, None

    def _close(self):
        """ Internal method - Closes the connection.
        
         Failure to do this may, in some situations, cause your Python
         interpreter to hang at shutdown (often due to race conditions).
         It's good practice to `close` your client objects anytime you're
         done using them, instead of relying on garbage collection.
        """
        self.ssh.close()

    def run_command(self, cmd):
        """ Runs an arbitrary command on a given remote destination.
        
        :param cmd: Command to execute on a remote host
        :type cmd: str
        :return: Tuple containing stdout and stderr
        :rtype: tuple
        """

        if self._connect():

            _, stdout, stderr = self._execute(cmd)

            if stdout.readable():
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    stdout = json.loads(stdout.read())
                    stderr = None
                else:
                    stdout = None
                    stderr = stderr.read()

            self._close()

            return stdout, stderr
        else:
            return None, None


class QemuGuestAgentAPI(ConnectionManager):

    def __init__(self, host_ipaddr, instance_name):
        ConnectionManager.__init__(self, host_ipaddr)
        self.host_ipaddr = host_ipaddr
        self.instance_name = instance_name

    def __getattr__(self, attr):
        """ Transforms any attribute into a QEMU query, validating it against
        the list of supported commands first.
        
        :param attr: Attribute to query
        :rtype dict
        """
        if self._validate(attr.replace("_", "-")):
            stdout, stderr = self.run_command(
                self._prepare_command(attr)
            )
        else:
            stdout = {"Command not implemented or supported by QEMU-GA"}
        return stdout

    def _prepare_command(self, cmd):
        """ Receives a command and turns it into a proper virsh command.
        
        :param cmd: QEMU-GA command
        :type cmd: str
        :rtype dict
        """
        query = "'{ \"execute\": \"%s\" }'" % cmd.replace("_", "-")

        command = "virsh qemu-agent-command %s %s" % (self.instance_name,
                                                      query)

        return command

    def _validate(self, cmd):

        stdout, stderr = self.run_command(
            self._prepare_command('guest-info')
        )

        if not stderr:

            for item in stdout['return']['supported_commands']:

                if unicode(cmd) in item.values():
                    return True

        return False

if __name__ == "__main__":

    qemu = QemuGuestAgentAPI(host_ipaddr='',
                             instance_name='')

    print qemu.guest_network_get_interfaces
