""" Controlls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import paramiko, subprocess, re, threading
from . import tf_cfg, remote, nginx, tempesta, siege

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


#-------------------------------------------------------------------------------
# Clients
#-------------------------------------------------------------------------------

class Client():
    """ Base class for managing HTTP benchmark utilities.

    Command-line options can be added by appending `Client.options` list.
    Also see comment in `Client.add_option_file()` function.
    """

    def __init__(self, bin, uri=''):
        """ `uri` must be relative to server root.

        DO NOT format command line options in constructor! Instead format them
        in `form_command()` function. This would allow to update options until
        client will be started. See `Wrk` class for example
        """
        self.node = remote.client
        self.connections = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        self.duration = int(tf_cfg.cfg.get('General', 'Duration'))
        self.set_uri(uri)
        self.bin = tf_cfg.cfg.get_binary('Client', bin)
        self.clear_stats()
        # List of command-line options.
        self.options = []
        # List tuples (filename, content) to create corresponding files on
        # remote node.
        self.files = []
        # List of files to be removed from remote node after client finish.
        self.cleanup_files = []

    def set_uri(self, uri):
        """ For some clients uri is an optional parameter, e.g. for Siege.
        They use file with list of uris instead. Don't force clients to use
        iri field.
        """
        if uri:
            server_addr = tf_cfg.cfg.get('Tempesta', 'ip')
            self.uri = ''.join(['http://', server_addr, uri])
        else:
            self.uri = ''

    def clear_stats(self):
        self.ret = False
        self.requests = 0
        self.errors = 0

    def cleanup(self):
        for file in self.cleanup_files:
            self.node.remove_file(file)

    def copy_files(self):
        for (name, content) in self.files:
            if not self.node.copy_file(name, content):
                return False
        return True

    def parse_out(self, ret, stdout, stderr):
        """ Parse framework results. """
        print(ret, stdout.decode('ascii'), stderr.decode('ascii'))

    def th_routine(self, command):
        self.ret, stdout, stderr = self.node.run_cmd(command,
            timeout = self.duration + 5)
        self.parse_out(self.ret, stdout, stderr)
        self.cleanup()

    def form_command(self):
        """ Prepare run command for benchmark to run on remote node. """
        cmd = ' '.join([self.bin] + self.options + [self.uri])
        return cmd

    def run(self):
        """ Run benchmark in background thread. """
        hostname = tf_cfg.cfg.get('Client', 'hostname')
        tf_cfg.dbg(3, '\tRun client on %s for %s seconds ...' %
                   (hostname, self.duration))

        cmd = self.form_command()

        self.clear_stats()
        if not self.copy_files():
            return
        self.th = threading.Thread(target=self.th_routine, args=(cmd,))
        self.th.start()

    def wait(self):
        """ Wait for completion. """
        # Thread might not exist if run() has failed.
        if hasattr(self, 'th'):
            self.th.join()

    def results(self):
        return self.ret, self.requests, self.errors

    def add_option_file(self, option, filename, content):
        """ Helper for using files as client options: normaly file must be
        copied to remote node, present in command line as parameter and
        removed after client finish.
        """
        dir = tf_cfg.cfg.get('Client', 'workdir')
        full_name = ''.join([dir, filename])
        self.files.append((filename, content))
        self.options.append('%s %s' % (option, full_name))
        self.cleanup_files.append(full_name)

    def set_user_agent(self, ua):
        self.options.append('-H \'User-Agent: %s\'' % ua)


class Wrk(Client):
    """ wrk - HTTP benchmark utility. """

    def __init__(self, threads=-1, uri='/'):
        Client.__init__(self, 'wrk', uri)
        self.threads = threads

    def form_command(self):
        self.options.append('-d %d' % self.duration)
        # At this moment threads equals user defined value or maximum theads
        # count for remote node.
        if self.threads == -1:
            self.threads = remote.get_max_thread_count(self.node)
        threads = self.threads if self.connections > 1 else 1
        self.options.append('-t %d' % threads)
        self.options.append('-c %d' % self.connections)
        return Client.form_command(self)

    def parse_out(self, ret, stdout, stderr):
        if not ret:
            # WRK failed, nothing to parse
            return
        m = re.search(b'(\d+) requests in ', stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(b'Non-2xx or 3xx responses: (\d+)', stdout)
        if m:
            self.errors = int(m.group(1))


class Ab(Client):
    """ Apache benchmark. """

    def __init__(self, uri='/'):
        Client.__init__(self, 'ab', uri = uri)

    def form_command(self):
        # Don't show progress.
        self.options.append('-q')
        self.options.append('-t %d' % self.duration)
        self.options.append('-c %d' % self.connections)
        return Client.form_command(self)

    def parse_out(self, ret, stdout, stderr):
        if not ret:
            return
        m = re.search(b'Complete requests:\s+(\d+)', stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(b'Non-2xx responses:\s+(\d+)', stdout)
        if m:
            self.errors = int(m.group(1))
        m = re.search(b'Failed requests:\s+(\d+)', stdout)
        if m:
            self.errors += int(m.group(1))


class Siege(Client):
    """ HTTP regression test and benchmark utility. """

    def __init__(self, uri='/'):
        Client.__init__(self, 'siege', uri = uri)
        self.rc = siege.Config()

    def form_command(self):
        # Benchmark: no delays between requests.
        self.options.append('-b')
        self.options.append('-t %dS' % self.duration)
        self.options.append('-c %d' % self.connections)
        # Add RC file.
        self.add_option_file('-R', self.rc.filename, self.rc.get_config())
        # Note: Siege sends statistics to stderr.
        return Client.form_command(self)

    def parse_out(self, ret, stdout, stderr):
        """ Siege prints results to stderr. """
        if not ret:
            return
        m = re.search(b'Successful transactions:\s+(\d+)', stderr)
        if m:
            self.requests = int(m.group(1))
        m = re.search(b'Failed transactions:\s+(\d+)', stderr)
        if m:
            self.errors = int(m.group(1))

    def set_user_agent(self, ua):
        self.options.append('-A \'%s\'' % ua)


#-------------------------------------------------------------------------------
# Tempesta
#-------------------------------------------------------------------------------


class Tempesta():

    def __init__(self):
        self.node = remote.tempesta
        self.workdir = self.node.workdir
        self.config_name = 'tempesta_fw.conf'
        self.config = tempesta.Config()
        self.stats = tempesta.Stats()
        self.host = tf_cfg.cfg.get('Tempesta', 'hostname')

    def start(self):
        tf_cfg.dbg(3, '\tStarting TempestaFW on %s' % self.host)
        self.stats.clear()
        # Use relative path to work dir to get rid of extra mkdir command.
        r = self.node.copy_file(''.join(['etc/', self.config_name]),
                                self.config.get_config())
        if not r:
            return False
        cmd = '%s/scripts/tempesta.sh --start' % self.workdir
        r, _, _ = self.node.run_cmd(cmd)
        return r

    def stop(self):
        """ Stop and unload all TempestaFW modules. """
        tf_cfg.dbg(3, '\tStoping TempestaFW on %s' % self.host)
        cmd = '%s/scripts/tempesta.sh --stop' % self.workdir
        r, _, _ = self.node.run_cmd(cmd)
        return r

    def get_stats(self):
        cmd = 'cat /proc/tempesta/perfstat'
        r, stdout, _ = self.node.run_cmd(cmd)
        if not r:
            return r
        self.stats.parse(stdout)
        return r

#-------------------------------------------------------------------------------
# Server
#-------------------------------------------------------------------------------

class Nginx():

    def __init__(self, listen_port, workers=1):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        self.config = nginx.Config(self.workdir, listen_port, workers)
        self.clear_stats()
        self.state = 'down'
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()

    def get_name(self):
        return ':'.join([self.node.host, str(self.config.port)])

    def start(self):
        if self.state != 'down':
            return False
        hostname = tf_cfg.cfg.get('Server', 'hostname')
        tf_cfg.dbg(3, '\tStarting Nginx on %s' % self.get_name())
        self.clear_stats()
        # Copy nginx config to working directory on 'server' host.
        r = self.node.copy_file(self.config.config_name, self.config.config)
        if not r:
            return False
        # Nginx forks on start, no background threads needed.
        config_file = ''.join([self.workdir, self.config.config_name])
        cmd = ' '.join([tf_cfg.cfg.get('Server', 'nginx'), '-c', config_file])
        r, _, _ = self.node.run_cmd(cmd, ignore_stderr=True)
        self.state = 'up' if r else 'error'
        return r

    def stop(self):
        if self.state != 'up':
            return True
        hostname = tf_cfg.cfg.get('Server', 'hostname')
        tf_cfg.dbg(3, '\tStoping Nginx on %s' % self.get_name())
        pid_file = ''.join([self.workdir, self.config.pidfile_name])
        config_file = ''.join([self.workdir, self.config.config_name])
        cmd = '[ -f %s ] && kill -s TERM $(cat %s)' % (pid_file, pid_file)
        r, _, _ = self.node.run_cmd(cmd, ignore_stderr=True)
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
        r, out, _ = self.node.run_cmd(cmd)
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
