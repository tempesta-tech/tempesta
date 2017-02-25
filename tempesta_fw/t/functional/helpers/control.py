""" Controlls node over SSH if remote, or via OS if local one. """

from __future__ import print_function
import abc
import re
import multiprocessing.dummy as multiprocessing
from . import tf_cfg, remote, nginx, tempesta, siege

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

    def __init__(self, binary, uri=''):
        """ `uri` must be relative to server root.

        DO NOT format command line options in constructor! Instead format them
        in `form_command()` function. This would allow to update options until
        client will be started. See `Wrk` class for example
        """
        self.node = remote.client
        self.connections = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        self.duration = int(tf_cfg.cfg.get('General', 'Duration'))
        self.workdir = tf_cfg.cfg.get('Client', 'workdir')
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
        self.requests = 0
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
        return self.requests, self.errors

    def add_option_file(self, option, filename, content):
        """ Helper for using files as client options: normaly file must be
        copied to remote node, present in command line as parameter and
        removed after client finish.
        """
        full_name = ''.join([self.workdir, filename])
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

    def parse_out(self, stdout, stderr):
        m = re.search(r'(\d+) requests in ', stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(r'Non-2xx or 3xx responses: (\d+)', stdout)
        if m:
            self.errors = int(m.group(1))
        return True


class Ab(Client):
    """ Apache benchmark. """

    def __init__(self, uri='/'):
        Client.__init__(self, 'ab', uri=uri)

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


class Siege(Client):
    """ HTTP regression test and benchmark utility. """

    def __init__(self, uri='/'):
        Client.__init__(self, 'siege', uri=uri)
        self.rc = siege.Config()
        self.copy_rc = True

    def form_command(self):
        # Benchmark: no delays between requests.
        self.options.append('-b')
        self.options.append('-t %dS' % self.duration)
        self.options.append('-c %d' % self.connections)
        # Add RC file.
        if self.copy_rc:
            self.add_option_file('-R', self.rc.filename, self.rc.get_config())
        else:
            self.options.append('-R %s%s' % (self.workdir, self.rc.filename))
        return Client.form_command(self)

    def parse_out(self, stdout, stderr):
        """ Siege prints results to stderr. """
        m = re.search(r'Successful transactions:\s+(\d+)', stderr)
        if m:
            self.requests = int(m.group(1))
        m = re.search(r'Failed transactions:\s+(\d+)', stderr)
        if m:
            self.errors = int(m.group(1))
        return True

    def set_user_agent(self, ua):
        self.options.append('-A \'%s\'' % ua)

#-------------------------------------------------------------------------------
# Client helpers
#-------------------------------------------------------------------------------

def client_run_blocking(client):
    tf_cfg.dbg(3, '\tRunning HTTP client on %s' % remote.client.host)
    assert client.prepare()
    stdout, stderr = remote.client.run_cmd(client.cmd)
    assert client.parse_out(stdout, stderr)
    client.cleanup()

def __clients_prepare(client):
    return client.prepare()

def __clients_run(client):
    return remote.client.run_cmd(client.cmd, timeout=(client.duration + 5))

def __clients_parse_output(args):
    client, (stdout, stderr) = args
    return client.parse_out(stdout, stderr)

def __clients_cleanup(client):
    return client.cleanup()

def clients_run_parallel(clients):
    tf_cfg.dbg(3, ('\tRunning %d HTTP clients on %s' %
                   (len(clients), remote.client.host)))
    if not len(clients):
        return True
    # In most cases all Siege instances use the same config file. no need to
    # copy in many times.
    if isinstance(clients[0], Siege):
        for i in range(1, len(clients)):
            clients[i].copy_rc = False

    pool = multiprocessing.Pool(len(clients))
    results = pool.map(__clients_prepare, clients)
    assert all(results), 'Some HTTP clients failed on prepare stage!'

    results = pool.map(__clients_run, clients)

    parse_args = [(clients[i], results[i]) for i in range(len(clients))]
    pool.map(__clients_parse_output, parse_args)
    pool.map(__clients_cleanup, clients)


#-------------------------------------------------------------------------------
# Tempesta
#-------------------------------------------------------------------------------


class Tempesta(object):

    def __init__(self):
        self.node = remote.tempesta
        self.workdir = self.node.workdir
        self.config_name = 'tempesta_fw.conf'
        self.config = tempesta.Config()
        self.stats = tempesta.Stats()
        self.host = tf_cfg.cfg.get('Tempesta', 'hostname')
        self.err_msg = ' '.join(["Can't %s TempestaFW on", self.host])

    def start(self):
        tf_cfg.dbg(3, '\tStarting TempestaFW on %s' % self.host)
        self.stats.clear()
        # Use relative path to work dir to get rid of extra mkdir command.
        self.node.copy_file(''.join(['etc/', self.config_name]),
                            self.config.get_config())
        cmd = '%s/scripts/tempesta.sh --start' % self.workdir
        self.node.run_cmd(cmd, err_msg=(self.err_msg % 'start'))

    def stop(self):
        """ Stop and unload all TempestaFW modules. """
        tf_cfg.dbg(3, '\tStoping TempestaFW on %s' % self.host)
        cmd = '%s/scripts/tempesta.sh --stop' % self.workdir
        self.node.run_cmd(cmd, err_msg=(self.err_msg % 'stop'))

    def get_stats(self):
        cmd = 'cat /proc/tempesta/perfstat'
        stdout, _ = self.node.run_cmd(cmd,
                                      err_msg=(self.err_msg % 'get stats of'))
        self.stats.parse(stdout)

#-------------------------------------------------------------------------------
# Server
#-------------------------------------------------------------------------------

class Nginx(object):

    def __init__(self, listen_port, workers=1):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        self.config = nginx.Config(self.workdir, listen_port, workers)
        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.err_msg = "Can't %s Nginx on %s"
        self.active_conns = 0
        self.requests = 0

    def get_name(self):
        return ':'.join([self.node.host, str(self.config.port)])

    def start(self):
        tf_cfg.dbg(3, '\tStarting Nginx on %s' % self.get_name())
        self.clear_stats()
        # Copy nginx config to working directory on 'server' host.
        self.node.copy_file(self.config.config_name, self.config.config)
        # Nginx forks on start, no background threads needed,
        # but it holds stderr open after demonisation.
        config_file = ''.join([self.workdir, self.config.config_name])
        cmd = ' '.join([tf_cfg.cfg.get('Server', 'nginx'), '-c', config_file])
        self.node.run_cmd(cmd, ignore_stderr=True,
                          err_msg=(self.err_msg % ('start', self.get_name())))

    def stop(self):
        tf_cfg.dbg(3, '\tStoping Nginx on %s' % self.get_name())
        pid_file = ''.join([self.workdir, self.config.pidfile_name])
        config_file = ''.join([self.workdir, self.config.config_name])
        cmd = '[ -f %s ] && kill -s TERM $(cat %s)' % (pid_file, pid_file)
        self.node.run_cmd(cmd, ignore_stderr=True,
                          err_msg=(self.err_msg % ('stop', self.get_name())))
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

def __servers_pool_size(n_servers):
    if remote.server.is_remote():
        # By default MasSessions in sshd config is 10. Do not overflow it.
        return 4
    else:
        return n_servers

def servers_start(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.start, servers)

def servers_stop(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.stop, servers)

def servers_get_stats(servers):
    threads = __servers_pool_size(len(servers))
    pool = multiprocessing.Pool(threads)
    pool.map(Nginx.get_stats, servers)
