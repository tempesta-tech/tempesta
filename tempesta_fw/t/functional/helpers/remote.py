""" Controlls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import re
import os
import abc
import paramiko
import subprocess32 as subprocess
from . import tf_cfg, framework

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Don't remove files from remote node. Helpful for tests development.
DEBUG_FILES = False


class Node(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, hostname, workdir):
        self.host = hostname
        self.workdir = workdir

    def is_remote(self):
        return self.host != 'localhost'

    @abc.abstractmethod
    def run_cmd(self, cmd, timeout=10, ignore_stderr=False, err_msg=''): pass

    @abc.abstractmethod
    def mkdir(self, path): pass

    @abc.abstractmethod
    def copy_file(self, filename, content, path=None): pass

    @abc.abstractmethod
    def remove_file(self, filename): pass


class LocalNode(Node):
    def __init__(self, hostname, workdir):
        Node.__init__(self, hostname, workdir)

    def run_cmd(self, cmd, timeout=10, ignore_stderr=False, err_msg=''):
        tf_cfg.dbg(4, "Run command '%s' on host %s" % (cmd, self.host))
        stdout = ''
        stderr = ''
        stderr_pipe = None if ignore_stderr else subprocess.PIPE
        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=stderr_pipe) as p:
            try:
                stdout, stderr = p.communicate(timeout)
                assert p.returncode == 0, "Return code is not 0."
            except Exception as e:
                if not err_msg:
                    err_msg = ("Error running command '%s' on %s: %s" %
                               (cmd, self.host, e))
                framework.bug(err_msg)
        return stdout, stderr

    def mkdir(self, path):
        try:
            os.makedirs(path)
        except OSError:
            if not os.path.isdir(path):
                raise

    def copy_file(self, filename, content, path=None):
        # Create dir first.
        if path == None:
            path = self.workdir
        else:
            self.mkdir(path)
        filename = ''.join([dir, filename])
        with open(filename, 'w') as f:
            f.write(content)


    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        if os.path.isfile(filename):
            os.remove(filename)


class RemoteNode(Node):
    def __init__(self, hostname, workdir, user, port=22):
        Node.__init__(self, hostname, workdir)
        self.user = user
        self.port = port
        self.connect()

    def connect(self):
        """ Open SSH connection to node if remote. Returns False on SSH errors.
        """
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.load_system_host_keys()
            # Workaround: paramiko prefer RSA keys to ECDSA, so add RSA
            # key to known_hosts.
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname=self.host, username=self.user,
                             port=self.port, timeout=5)
        except Exception as e:
            framework.bug("Error connecting %s: %s" % (self.host, e))

    def close(self):
        """ Release SSH connection without waitning for GC. """
        self.ssh.close()

    def run_cmd(self, cmd, timeout=10, ignore_stderr=False, err_msg=''):
        tf_cfg.dbg(4, "Run command '%s' on host %s" % (cmd, self.host))
        stderr = ''
        stdout = ''
        try:
            _, out_f, err_f = self.ssh.exec_command(cmd, timeout=timeout)
            stdout = out_f.read()
            if not ignore_stderr:
                stderr = err_f.read()
            assert out_f.channel.recv_exit_status() == 0, "Return code is not 0."
        except Exception as e:
            if not err_msg:
                err_msg = ("Error running command '%s' on %s: %s" %
                           (cmd, self.host, e))
            framework.bug(err_msg)
        return stdout, stderr

    def mkdir(self, path):
        self.run_cmd('mkdir -p %s' % path)

    def copy_file(self, filename, content, path=None):
        # Create directory it is not default workdir.
        if path == None:
            path = self.workdir
        else:
            self.mkdir(path)
        filename = ''.join([path, filename])
        try:
            sftp = self.ssh.open_sftp()
            sfile = sftp.file(filename, 'w', -1)
            sfile.write(content)
            sfile.flush()
            sftp.close()
        except Exception as e:
            framework.bug(("Error copying file %s to %s: %s" %
                           (filename, self.host, e)))

    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        try:
            sftp = self.ssh.open_sftp()
            sftp.unlink(filename)
            sftp.close()
        except Exception as e:
            framework.bug(("Error removing file %s on %s: %s" %
                           (filename, self.host, e)))



def create_node(host):
    hostname = tf_cfg.cfg.get(host, 'hostname')
    workdir = tf_cfg.cfg.get(host, 'workdir')

    if hostname != 'localhost':
        port = int(tf_cfg.cfg.get(host, 'port'))
        username = tf_cfg.cfg.get(host, 'user')
        return RemoteNode(hostname, workdir, username, port)
    return LocalNode(hostname, workdir)


#-------------------------------------------------------------------------------
# Helper functions.
#-------------------------------------------------------------------------------

def get_max_thread_count(node):
    out, _ = node.run_cmd('grep -c processor /proc/cpuinfo')
    m = re.match(r'^(\d+)$', out)
    if not m:
        return 1
    return int(m.group(1).decode('ascii'))

#-------------------------------------------------------------------------------
# Global accessable SSH/Local connections
#-------------------------------------------------------------------------------
client = create_node('Client')
tempesta = create_node('Tempesta')
server = create_node('Server')

# Create working directories on client and server nodes. Work directory on
# Tempesta contains sources and must exist.
for node in [client, server]:
    node.mkdir(node.workdir)
