""" Controlls node over SSH if remote, or via OS if local one. """

import paramiko, subprocess, re, threading
from . import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

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
        except paramiko.ssh_exception.SSHException as e:
            print('SSH connection error:', e)
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
            except paramiko.ssh_exception.SSHException as e:
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
        if not dir.endswith('/'):
            dir = dir + '/'
        filename = dir + filename
        if self.remote:
            try:
                sftp = self.ssh.open_sftp()
                sfile = sftp.file(filename, 'w', -1)
                sfile.write(content)
                sfile.flush()
                sftp.close()
            except paramiko.ssh_exception.SSHException as e:
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
        if self.remote:
            try:
                sftp = self.ssh.open_sftp()
                sftp.unlink(filename)
                sftp.close()
            except paramiko.ssh_exception.SSHException as e:
                print('SSH connection error:', e)
                return False
            return True
        else:
            if os.path.isfile(path):
                    os.remove(path)
            return True

#-------------------------------------------------------------------------------
# ARP configuration
#-------------------------------------------------------------------------------
class ArpSetter():
    """ Set ARP/Neighbour static entries on Node. """

    def __init__(self, node):
        self.node = node
        self.machine = node.machine

    def fill_arp(self):
        if self.machine == 'Client':
            return self.add_neigh('Tempesta')
        if self.machine == 'Tempesta':
            return self.add_neigh('Client') and self.add_neigh('Server')
        if self.machine == 'Server':
            return self.add_neigh('Tempesta')

    def is_same_machine(self, machine):
        assert(machine != self.machine)
        return (tf_cfg.cfg.get(self.machine, 'hostname') ==
                tf_cfg.cfg.get(machine, 'hostname'))

    def add_neigh(self, neigh):
        """ Fill neighbour tables in order not to waist cycles for ARP/Neighbour
        protocol and make tests more stressfull

        This is done by executing two commands:
        Retrieve target net device
        # ip -o addr show | grep ${machine_ip} | awk '{print $2}'
        Set neigbour address:
        # ip neighbor add ${ip} lladdr ${hw_addr} dev ${dev} nud permanent
        """
        if self.is_same_machine(neigh):
            return # Nothing to do.

        node_ip = tf_cfg.cfg.get(self.node.machine, 'Ip')
        neigh_ip = tf_cfg.cfg.get(neigh, 'Ip')
        neigh_hwa = tf_cfg.cfg.get(neigh, 'Mac')
        if (node_ip == '127.0.0.1' or
            neigh_ip == '127.0.0.1' or neigh_hwa == 'ff:ff:ff:ff:ff:ff'):
            return
        cmd = 'ip -o addr show | grep %s | awk \'{print $2}\'' % node_ip
        ret, iface = self.node.run_cmd(cmd)
        if ret and re.match(b'^(\w+)$', iface):
            dev = re.match(b'^(\w+)$', iface).group(1).decode('ascii')
            cmd = ('ip neighbor add %s lladdr %s dev %s nud permanent' %
                   (neigh_ip, neigh_hwa, dev))
            ret, _ = self.node.run_cmd(cmd)
        return ret

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

# Setup ARP tables once.
if tf_cfg.cfg.get('General', 'ARP') == 'True':
    for m in [client, tempesta, server]:
        setter = ArpSetter(m)
        assert(setter.fill_arp())
