""" Controls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import abc
import re
import os
import asyncore
import multiprocessing.dummy as multiprocessing
from . import tf_cfg, remote, error, nginx, tempesta, deproxy, stateful

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

#-------------------------------------------------------------------------------
# Clients
#-------------------------------------------------------------------------------


class Client(object):
    __metaclass__ = abc.ABCMeta
    """ Base class for managing HTTP benchmark utilities.

    Command-line options can be added by appending `Client.options` list.
    Also see comment in `Client.add_option_file()` function.
    """

    def __init__(self, binary, uri='', ssl=False):
        """ `uri` must be relative to server root.

        DO NOT format command line options in constructor! Instead format them
        in `form_command()` function. This would allow to update options until
        client will be started. See `Wrk` class for example
        """
        self.node = remote.client
        self.connections = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        self.duration = int(tf_cfg.cfg.get('General', 'Duration'))
        self.workdir = tf_cfg.cfg.get('Client', 'workdir')
        self.ssl = ssl
        self.set_uri(uri)
        self.bin = tf_cfg.cfg.get_binary('Client', binary)
        self.cmd = ''
        self.clear_stats()
        # List of command-line options.
        self.options = []
        # List tuples (filename, content) to create corresponding files on
        # remote node.
        self.files = []
        # List of files to be removed from remote node after client finish.
        self.cleanup_files = []
        self.requests = 0
        self.rate = -1
        self.errors = 0

    def set_uri(self, uri):
        """ For some clients uri is an optional parameter, e.g. for Siege.
        They use file with list of uris instead. Don't force clients to use
        uri field.
        """
        if uri:
            proto = 'https://' if self.ssl else 'http://'
            server_addr = tf_cfg.cfg.get('Tempesta', 'ip')
            self.uri = ''.join([proto, server_addr, uri])
        else:
            self.uri = ''

    def clear_stats(self):
        self.requests = 0
        self.rate = -1
        self.errors = 0

    def cleanup(self):
        for f in self.cleanup_files:
            self.node.remove_file(f)

    def copy_files(self):
        for (name, content) in self.files:
            self.node.copy_file(name, content)

    @abc.abstractmethod
    def parse_out(self, stdout, stderr):
        """ Parse framework results. """
        print(stdout.decode('ascii'), stderr.decode('ascii'))
        return True

    def form_command(self):
        """ Prepare run command for benchmark to run on remote node. """
        cmd = ' '.join([self.bin] + self.options + [self.uri])
        return cmd

    def prepare(self):
        self.cmd = self.form_command()
        self.clear_stats()
        self.copy_files()
        return True

    def results(self):
        if (self.rate == -1):
            self.rate = self.requests / self.duration
        return self.requests, self.errors, self.rate

    def add_option_file(self, option, filename, content):
        """ Helper for using files as client options: normaly file must be
        copied to remote node, present in command line as parameter and
        removed after client finish.
        """
        full_name = os.path.join(self.workdir, filename)
        self.files.append((filename, content))
        self.options.append('%s %s' % (option, full_name))
        self.cleanup_files.append(full_name)

    def set_user_agent(self, ua):
        self.options.append('-H \'User-Agent: %s\'' % ua)


class Wrk(Client):
    """ wrk - HTTP benchmark utility.

    Wrk counts statistics of bad socket operations: errors on opening, reading
    from and writing to sockets, error of HTTP message parsing and so on.
    If FAIL_ON_SOCK_ERR is set assert that none of such errors happened during
    test, otherwise print warning and count the errors as usual errors.
    """
    FAIL_ON_SOCK_ERR=True

    def __init__(self, threads=-1, uri='/', ssl=False):
        Client.__init__(self, binary='wrk', uri=uri, ssl=ssl)
        self.threads = threads
        self.script = ''
        self.local_scriptdir = ''.join([os.path.dirname(os.path.realpath(__file__)), '/../wrk/'])
        self.copy_script = True

    def set_script(self, script, need_copy=True):
        self.script = script + ".lua"
        self.copy_script = need_copy

    def append_script_option(self):
        if not self.script:
            return
        script_path = self.workdir + "/" + self.script

        if self.copy_script:
            local_path = ''.join([self.local_scriptdir, self.script])
            local_script_path = os.path.abspath(local_path)
            assert os.path.isfile(local_script_path), \
                   'No script found: %s !' % local_script_path
            f = open(local_script_path, 'r')
            self.files.append((self.script, f.read()))

        self.options.append('-s %s' % script_path)

    def form_command(self):
        self.options.append('-d %d' % self.duration)
        # At this moment threads equals user defined value or maximum theads
        # count for remote node.
        if self.threads == -1:
            self.threads = remote.get_max_thread_count(self.node)
        threads = self.threads if self.connections > 1 else 1
        self.options.append('-t %d' % threads)
        self.options.append('-c %d' % self.connections)
        self.append_script_option()
        return Client.form_command(self)

    def parse_out(self, stdout, stderr):
        m = re.search(r'(\d+) requests in ', stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(r'Non-2xx or 3xx responses: (\d+)', stdout)
        if m:
            self.errors = int(m.group(1))
        m = re.search(r'Requests\/sec:\s+(\d+)', stdout)
        if m:
            self.rate = int(m.group(1))

        sock_err_msg = "Socket errors on wrk. Too many concurrent connections?"
        m = re.search(r'(Socket errors:.+)', stdout)
        if self.FAIL_ON_SOCK_ERR:
            assert not m, sock_err_msg
        if m:
            tf_cfg.dbg(1, "WARNING! %s" % sock_err_msg)
            err_m = re.search(r'\w+ (\d+), \w+ (\d+), \w+ (\d+), \w+ (\d+)',
                              m.group(1))
            self.errors += (int(err_m.group(1)) + int(err_m.group(2))
                            + int(err_m.group(3)) + int(err_m.group(4)))
        return True


class Ab(Client):
    """ Apache benchmark. """

    def __init__(self, uri='/', ssl=False):
        Client.__init__(self, 'ab', uri=uri, ssl=ssl)

    def form_command(self):
        # Don't show progress.
        self.options.append('-q')
        self.options.append('-t %d' % self.duration)
        self.options.append('-c %d' % self.connections)
        return Client.form_command(self)

    def parse_out(self, stdout, stderr):
        m = re.search(r'Complete requests:\s+(\d+)', stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(r'Non-2xx responses:\s+(\d+)', stdout)
        if m:
            self.errors = int(m.group(1))
        m = re.search(r'Failed requests:\s+(\d+)', stdout)
        if m:
            self.errors += int(m.group(1))
        return True


#-------------------------------------------------------------------------------
# Client helpers
#-------------------------------------------------------------------------------

def client_run_blocking(client):
    """ User must call client.prepare() before calling the function and
    client.cleanup() after the call if applied.
    """
    tf_cfg.dbg(3, '\tRunning HTTP client on %s' % remote.client.host)
    stdout, stderr = remote.client.run_cmd(client.cmd,
                                           timeout=(client.duration + 5))
    tf_cfg.dbg(3, stdout, stderr)
    error.assertTrue(client.parse_out(stdout, stderr))

def __clients_prepare(client):
    return client.prepare()

def __clients_run(client):
    return remote.client.run_cmd(client.cmd, timeout=(client.duration + 5))

def __clients_parse_output(args):
    client, (stdout, stderr) = args
    tf_cfg.dbg(3, stdout, stderr)
    return client.parse_out(stdout, stderr)

def __clients_cleanup(client):
    return client.cleanup()

def clients_run_parallel(clients):
    tf_cfg.dbg(3, ('\tRunning %d HTTP clients on %s' %
                   (len(clients), remote.client.host)))
    if not clients:
        return

    pool = multiprocessing.Pool(len(clients))
    results = pool.map(__clients_prepare, clients)
    error.assertTrue(all(results),
                     'Some HTTP clients failed on prepare stage!')

    results = pool.map(__clients_run, clients)

    parse_args = [(clients[i], results[i]) for i in range(len(clients))]
    pool.map(__clients_parse_output, parse_args)
    pool.map(__clients_cleanup, clients)

def clients_parallel_load(client, count=None):
    """ Spawn @count processes without parsing output. Just make high load.
    Python is too slow to spawn multiple (>100) processes.
    """
    if count is None:
        count = min(int(tf_cfg.cfg.get('General', 'concurrent_connections')), 1000)
    tf_cfg.dbg(3, ('\tRunning %d HTTP clients on %s' %
                   (count, remote.client.host)))
    error.assertTrue(client.prepare())
    cmd = 'seq %d | xargs -Iz -P1000 %s -q' % (count, client.cmd)

    pool = multiprocessing.Pool(2)
    results = pool.map(remote.client.run_cmd, [client.cmd, cmd])

    stdout, stderr = results[0]
    client.parse_out(stdout, stderr)
    client.cleanup()

#-------------------------------------------------------------------------------
# Tempesta
#-------------------------------------------------------------------------------
class Tempesta(stateful.Stateful):
    def __init__(self):
        self.node = remote.tempesta
        self.workdir = self.node.workdir
        self.config_name = os.path.join(self.workdir,
                                        tf_cfg.cfg.get('Tempesta', 'config'))
        self.config = tempesta.Config()
        self.stats = tempesta.Stats()
        self.host = tf_cfg.cfg.get('Tempesta', 'hostname')
        self.err_msg = ' '.join(["Can't %s TempestaFW on", self.host])
        self.stop_procedures = [self.stop_tempesta, self.remove_config]

    def run_start(self):
        tf_cfg.dbg(3, '\tStarting TempestaFW on %s' % self.host)
        self.stats.clear()
        self.node.copy_file(self.config_name, self.config.get_config())
        cmd = '%s/scripts/tempesta.sh --start' % self.workdir
        env = { 'TFW_CFG_PATH': self.config_name }
        self.node.run_cmd(cmd, timeout=30, env=env,
                          err_msg=(self.err_msg % 'start'))

    def stop_tempesta(self):
        tf_cfg.dbg(3, '\tStoping TempestaFW on %s' % self.host)
        cmd = '%s/scripts/tempesta.sh --stop' % self.workdir
        self.node.run_cmd(cmd, timeout=30, err_msg=(self.err_msg % 'stop'))

    def remove_config(self):
        self.node.remove_file(self.config_name)

    def reload(self):
        """Live reconfiguration"""
        tf_cfg.dbg(3, '\tReconfiguring TempestaFW on %s' % self.host)
        self.node.copy_file(self.config_name, self.config.get_config())
        cmd = '%s/scripts/tempesta.sh --reload' % self.workdir
        env = { 'TFW_CFG_PATH': self.config_name }
        self.node.run_cmd(cmd, timeout=30, env=env,
                          err_msg=(self.err_msg % 'reload'))

    def get_stats(self):
        cmd = 'cat /proc/tempesta/perfstat'
        stdout, _ = self.node.run_cmd(cmd,
                                      err_msg=(self.err_msg % 'get stats of'))
        self.stats.parse(stdout)

    def get_server_stats(self, path):
        cmd = 'cat /proc/tempesta/servers/%s' % (path)
        return self.node.run_cmd(cmd,
                                 err_msg=(self.err_msg % 'get stats of'))


class TempestaFI(Tempesta):
    """ Tempesta class for testing with fault injection."""

    def __init__(self, stap_script, mod=False, mod_name='stap_tempesta'):
        Tempesta.__init__(self)
        self.stap = ''.join([stap_script, '.stp'])
        self.module_stap = mod
        self.module_name = mod_name
        if self.module_stap:
            self.stap_msg = 'Cannot %s stap %s Tempesta.'
            self.modules_dir = '/lib/modules/$(uname -r)/custom/'
        else:
            self.stap_msg = 'Cannot %s stap %s kernel.'
        self.stop_procedures = [self.letout, self.letout_finish,
                                self.stop_tempesta, self.remove_config]

    def inject_prepare(self):
        if self.module_stap:
            self.node.run_cmd('mkdir %s' % self.modules_dir)
            cmd = 'find %s/ -name "*.ko" | xargs cp -t %s'
            self.node.run_cmd(cmd % (self.workdir, self.modules_dir))

    def inject(self):
        cmd = 'stap -g -m %s -F %s/tempesta_fw/t/functional/systemtap/%s'
        self.node.run_cmd(cmd % (self.module_name, self.workdir, self.stap),
                          timeout=30, err_msg=(self.stap_msg %
                                               ('inject', 'into')))

    def letout(self):
        cmd = 'rmmod %s' % self.module_name
        self.node.run_cmd(cmd, timeout=30, err_msg=(self.stap_msg %
                                                    ('remove', 'from')))
        self.node.remove_file(''.join([self.module_name, '.ko']))

    def letout_finish(self):
        if self.module_stap:
            self.node.run_cmd('rm -r %s' % self.modules_dir)

    def run_start(self):
        Tempesta.run_start(self)
        self.inject_prepare()
        self.inject()

#-------------------------------------------------------------------------------
# Server
#-------------------------------------------------------------------------------

class Nginx(stateful.Stateful):
    def __init__(self, listen_port, workers=1):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        self.ip = tf_cfg.cfg.get('Server', 'ip')
        self.config = nginx.Config(self.workdir, listen_port, workers)
        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.err_msg = "Can't %s Nginx on %s"
        self.active_conns = 0
        self.requests = 0
        self.stop_procedures = [self.stop_nginx, self.remove_config]

    def get_name(self):
        return ':'.join([self.ip, str(self.config.port)])

    def run_start(self):
        tf_cfg.dbg(3, '\tStarting Nginx on %s' % self.get_name())
        self.clear_stats()
        # Copy nginx config to working directory on 'server' host.
        self.node.copy_file(self.config.config_name, self.config.config)
        # Nginx forks on start, no background threads needed,
        # but it holds stderr open after demonisation.
        config_file = os.path.join(self.workdir, self.config.config_name)
        cmd = ' '.join([tf_cfg.cfg.get('Server', 'nginx'), '-c', config_file])
        self.node.run_cmd(cmd, ignore_stderr=True,
                          err_msg=(self.err_msg % ('start', self.get_name())))

    def stop_nginx(self):
        tf_cfg.dbg(3, '\tStoping Nginx on %s' % self.get_name())
        pid_file = os.path.join(self.workdir, self.config.pidfile_name)
        cmd = ' && '.join([
            '[ -e \'%s\' ]' % pid_file,
            'pid=$(cat %s)' % pid_file,
            'kill -s TERM $pid',
            'while [ -e \'/proc/$pid\' ]; do sleep 1; done'
        ])
        self.node.run_cmd(cmd, ignore_stderr=True,
                          err_msg=(self.err_msg % ('stop', self.get_name())))

    def remove_config(self):
        tf_cfg.dbg(3, '\tRemoving Nginx config for %s' % self.get_name())
        config_file = os.path.join(self.workdir, self.config.config_name)
        self.node.remove_file(config_file)

    def get_stats(self):
        """ Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self.stats_ask_times += 1
        # In default tests configuration Nginx status available on
        # `nginx_status` page.
        uri = 'http://%s:%d/nginx_status' % (self.node.host, self.config.port)
        cmd = 'curl %s' % uri
        out, _ = remote.client.run_cmd(
            cmd, err_msg=(self.err_msg % ('get stats of', self.get_name())))
        m = re.search(r'Active connections: (\d+) \n'
                      r'server accepts handled requests\n \d+ \d+ (\d+)',
                      out)
        if m:
            # Current request increments active connections for nginx.
            self.active_conns = int(m.group(1)) - 1
            # Get rid of stats requests influence to statistics.
            self.requests = int(m.group(2)) - self.stats_ask_times

    def clear_stats(self):
        self.active_conns = 0
        self.requests = 0
        self.stats_ask_times = 0

#-------------------------------------------------------------------------------
# Server helpers
#-------------------------------------------------------------------------------

MAX_THREADS = 32

def __servers_pool_size(n_servers):
    if remote.server.is_remote():
        # By default MaxSessions in sshd config is 10. Do not overflow it.
        return 4
    return min(n_servers, MAX_THREADS)

def servers_start(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.start, servers)

def servers_force_stop(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.force_stop, servers)

def servers_stop(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.stop, servers)

def servers_get_stats(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.get_stats, servers)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
