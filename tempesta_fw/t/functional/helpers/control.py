""" Controlls node over SSH if remote, or via OS if local one. """

import paramiko, subprocess, re, threading
from . import tf_cfg, remote, nginx, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


#-------------------------------------------------------------------------------
# Clients
#-------------------------------------------------------------------------------

class Client():
    """ Base class for managing HTTP benchmark utilities. """

    def __init__(self, type, threads=-1, connections=-1, uri='/'):
        self.node = remote.client
        self.threads = threads
        self.connections = connections
        self.uri = uri

    def run(self):
        """ Run benchmark in background thread. """
        hostname = tf_cfg.cfg.get('Client', 'hostname')
        duration = tf_cfg.cfg.get('General', 'Duration')
        tf_cfg.dbg('\tRun client on %s for %s seconds ...' %
                   (hostname, duration))
        if self.threads == -1:
            ret, out = self.node.run_cmd('grep -c processor /proc/cpuinfo')
            if (not ret) or (not re.match(b'^\d+$', out)):
                return False
            self.threads = re.match(b'^(\d+)$', out).group(1).decode('ascii')

        bin = tf_cfg.cfg.get('Client', 'wrk')
        server_addr = tf_cfg.cfg.get('Tempesta', 'ip')
        cmd = self.form_command(bin, duration, server_addr)

        self.requests = 0
        self.errors = 0
        self.th = threading.Thread(target=self.th_routine,
                                   args=(cmd, int(duration),))
        self.th.start()

    def wait(self):
        """ Wait for completion. """
        self.th.join()

    def results(self):
        return self.ret, self.requests, self.errors

    def th_routine(self, command, duration):
        self.ret, out = self.node.run_cmd(command, timeout = duration * 2)
        self.parse_out(self.ret, out)

    def parse_out(self, ret, out):
        """ Parse framework results. """
        print(ret, out.decode('ascii'))

    def form_command(self, bin, duration, server_addr):
        """ Prepare run command for benchmark to run on remote node. """
        cmd = bin +' -t ' + duration + ' http://' + server_addr + self.uri
        return cmd



class Wrk(Client):

    def __init__(self, threads=-1, connections=-1, uri='/', script='',
                 headers=[]):
        Client.__init__(self, 'wrk', threads, connections, uri)

    def form_command(self, bin, duration, server_addr):
        cmd = (bin + ' -t ' + str(self.threads) + ' -d ' + duration +
               ' http://' + server_addr + self.uri)
        return cmd

    def parse_out(self, ret, out):
        if not ret:
            # WRK failed, nothing to parse
            return
        m = re.search(b'(\d+) requests in ', out)
        if m:
            self.requests = int(m.group(1))
        m = re.search(b'Non-2xx or 3xx responses: (\d+)', out)
        if m:
            self.errors = int(m.group(1))

#-------------------------------------------------------------------------------
# Tempesta
#-------------------------------------------------------------------------------


class Tempesta():

    def __init__(self):
        self.node = remote.tempesta
        self.workdir = tf_cfg.cfg.get('Tempesta', 'dir')
        if not self.workdir.endswith('/'):
            self.workdir = self.workdir + '/'
        self.config_name = 'tempesta_fw.conf'
        self.config = tempesta.Config()
        self.stats = tempesta.Stats()

    def start(self):
        hostname = tf_cfg.cfg.get('Tempesta', 'hostname')
        tf_cfg.dbg('\tStarting TempestaFW on %s' % hostname)
        self.stats.clear()
        r = self.node.copy_file(self.workdir + 'etc/', self.config_name,
                                self.config.get_config())
        if not r:
            return False
        cmd = '%s/scripts/tempesta.sh --start' % self.workdir
        r, _ = self.node.run_cmd(cmd)
        return r

    def stop(self):
        """ Stop and unload all TempestaFW modules. """
        hostname = tf_cfg.cfg.get('Tempesta', 'hostname')
        tf_cfg.dbg('\tStoping TempestaFW on %s' % hostname)
        cmd = '%s/scripts/tempesta.sh --stop' % self.workdir
        r, _ = self.node.run_cmd(cmd)
        return r

    def get_stats(self):
        cmd = 'cat /proc/tempesta/perfstat'
        r, out = self.node.run_cmd(cmd)
        if not r:
            return r
        self.stats.parse(out)
        return r

#-------------------------------------------------------------------------------
# Server
#-------------------------------------------------------------------------------

class Nginx():

    def __init__(self, listen_port, workers=1):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        if not self.workdir.endswith('/'):
            self.workdir = self.workdir + '/'
        self.config = nginx.Config(self.workdir, listen_port, workers)
        self.clear_stats()
        self.state = 'down'
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()

    def start(self):
        if self.state != 'down':
            return False
        hostname = tf_cfg.cfg.get('Server', 'hostname')
        tf_cfg.dbg('\tStarting Nginx on %s:%d' % (hostname, self.config.port))
        self.clear_stats()
        # Copy nginx config to working directory on 'server' host.
        r = self.node.copy_file(self.workdir, self.config.config_name,
                                self.config.config)
        if not r:
            return False
        # Nginx forks on start, no background threads needed.
        config_file = self.workdir + self.config.config_name
        cmd = tf_cfg.cfg.get('Server', 'nginx') + ' -c ' + config_file
        r, _ = self.node.run_cmd(cmd)
        self.state = 'up' if r else 'error'
        return r

    def stop(self):
        if self.state != 'up':
            return True
        hostname = tf_cfg.cfg.get('Server', 'hostname')
        tf_cfg.dbg('\tStoping Nginx on %s:%d' % (hostname, self.config.port))
        pid_file = self.workdir + self.config.pidfile_name
        config_file = self.workdir + self.config.config_name
        cmd = '[ -f %s ] && kill -s TERM $(cat %s)' % (pid_file, pid_file)
        r, _ = self.node.run_cmd(cmd)
        r &= self.node.remove_file(config_file)
        self.state = 'down' if r else 'error'
        return r

    def get_stats(self):
        """ Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self.stats_ask_times += 1
        # Just ask servver to get stats for us. 'node.run_cmd' will also tell
        # us if server is dead.
        uri = 'http://localhost:%d/nginx_status' % self.config.port
        cmd = 'curl %s' % uri
        r, out = self.node.run_cmd(cmd)
        if not r:
            return False, None
        m = re.search(b'Active connections: (\d+) \nserver accepts handled requests\n \d+ \d+ (\d+)',
                      out)
        if m:
            # Current request increments active connections for nginx.
            self.active_conns = int(m.group(1)) - 1
            # Get rid of stats requests influence to statistics.
            self.requests = int(m.group(2)) - self.stats_ask_times
        return r

    def clear_stats(self):
        self.active_conns = 0
        self.requests = 0
        self.stats_ask_times = 0
