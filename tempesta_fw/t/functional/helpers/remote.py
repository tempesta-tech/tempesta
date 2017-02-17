""" Controlls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import paramiko, subprocess, re, threading
from . import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Don't remove files from remote node. Helpful for tests development.
debug_files = False

class Node:
    """ Node representation: can be local machine or remote one. Helps running
    commands on remote hosts.
    """

    def __init__(self, machine):
        self.machine = machine
        self.host = tf_cfg.cfg.get(machine, 'hostname')

        self.remote = (self.host != 'localhost')
        if self.remote:
            self.user = tf_cfg.cfg.get(machine, 'user')
            self.port = int(tf_cfg.cfg.get(machine, 'port'))
        assert(self.connect())

    def connect(self):
        """ Open SSH connection to node if remote. Returns False on SSH errors.
        """
        if not self.remote:
            return True
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.load_system_host_keys()
            # Workaround: paramiko prefer RSA keys to ECDSA, so add RSA
            # key to known_hosts.
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname = self.host, username = self.user,
                             port = self.port, timeout = 5)
        except Exception as e:
            print('Remote host connection error:', e)
            return False
        return True

    def close(self):
        """ Release SSH connection without waitning for GC. """
        if not self.remote:
            return
        self.ssh.close()

    def run_cmd(self, cmd, timeout=10):
        """ Run command on remote or local host.

        Returns (return_code, stdout) if node available, (False, None)
        otherwise.
        """
        ret = False
        if self.remote:
            try:
                stdin, stdout, stderr = self.ssh.exec_command(cmd,
                                                              timeout=timeout)
                out = stdout.read() + stderr.read()
                ret = stdout.channel.recv_exit_status() == 0
            except Exception as e:
                print('SSH connection error:', e)
                return False, None
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            out = proc.communicate()[0]
            ret = proc.returncode == 0
        return ret, out

    def copy_file(self, dir, filename, content):
        """ Create file `dir`/`filename` on node with specified `content`.

        Returns False on errors.
        """
        # Create dir first.
        r, _ = self.run_cmd('mkdir -p %s' % dir)
        if not r:
            return False # SSH error or no enough rights.
        filename = dir + filename
        if self.remote:
            try:
                sftp = self.ssh.open_sftp()
                sfile = sftp.file(filename, 'w', -1)
                sfile.write(content)
                sfile.flush()
                sftp.close()
            except Exception as e:
                print('SSH connection error:', e)
                return False
            return True
        else:
            with open(filename, 'w') as file:
                file.write(content)
                return True
            return False

    def remove_file(self, filename):
        """ Remove `filename` from node. """
        if debug_files:
            return True
        if self.remote:
            try:
                sftp = self.ssh.open_sftp()
                sftp.unlink(filename)
                sftp.close()
            except Exception as e:
                print('SSH connection error:', e)
                return False
            return True
        else:
            if os.path.isfile(path):
                    os.remove(path)
            return True

#-------------------------------------------------------------------------------
# Helper functions.
#-------------------------------------------------------------------------------

def get_max_thread_count(node):
    ret, out = node.run_cmd('grep -c processor /proc/cpuinfo')
    if (not ret) or (not re.match(b'^\d+$', out)):
        return 1
    threads = int(re.match(b'^(\d+)$', out).group(1).decode('ascii'))
    return threads

#-------------------------------------------------------------------------------
# Global accessable SSH/Local connections
#-------------------------------------------------------------------------------
client = Node('Client')
tempesta = Node('Tempesta')
server = Node('Server')
