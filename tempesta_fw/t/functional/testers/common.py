__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from helpers import tf_cfg, control, stateful, remote, tempesta, deproxy
from very_many_backends import multi_backend
import unittest

class ListenerCode(object):
    """ Server listner info """
    port = 80
    ip_listen = "0.0.0.0"
    code = 200
    config = ""
    config_have_status = """
    location /nginx_status {
            stub_status on;
        }
"""
    config_server_template = """
    server {
        listen        %s;

        location / {
            return %d;
        }
        %s
    }
"""
    def __init__(self, ip_listen, port, code,
                 backlog=None, has_status=False):
        if backlog is None:
            listen_str = "%s:%i" % (ip_listen, port)
        else:
            listen_str = "%s:%i backlog=%s" % (ip_listen, port, backlog)
        self.ip_listen = ip_listen
        self.port = port
        self.code = code
        if has_status:
            self.config = self.config_server_template % \
                (listen_str, code, self.config_have_status)
        else:
            self.config = self.config_server_template % \
                (listen_str, code, "")

class NginxConfig(multi_backend.ConfigMultiplePorts):
    __servers_id = {}

    def add_server_location(self, ip_listen, port, location, id):
        if len(self.listeners) == 0:
            listener = multi_backend.Listener(ip_listen, port, location,
                                              has_status=True)
        else:
            listener = multi_backend.Listener(ip_listen, port, location)
        self.listeners.append(listener)
        self.__servers_id[id] = listener
        self.build_config()

    def add_server_code(self, ip_listen, port, code, id):
        if len(self.listeners) == 0:
            listener = ListenerCode(ip_listen, port, code,
                                              has_status=True)
        else:
            listener = ListenerCode(ip_listen, port, code)
        self.listeners.append(listener)
        self.__servers_id[id] = listener
        self.build_config()

    def get_server(self, id):
        if not self.__servers_id.has_key(id):
            return None
        return self.__servers_id[id]

class Nginx(control.Nginx):
    """ Nginx class """

    def __init__(self, workers=1):
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')
        self.config = NginxConfig(self.workdir, workers)
        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.err_msg = "Can't %s Nginx on %s"
        self.active_conns = 0
        self.requests = 0
        self.stop_procedures = [self.stop_nginx, self.remove_config]

class TempestaTest(unittest.TestCase):
    """ Test for tempesta """

    backends = []

    clients = []

    tempesta = {
        'listen_ip' : 'default',
        'listen_port' : 80,
        'backends' : [],
    }

    __servers = {}
    __clients = {}
    __tempesta = None

    def __create_client_deproxy(self, client):
        clt = deproxy.Client()
        return clt

    def __create_client_wrk(self, client):
        wrk = control.Wrk()
        return wrk

    def __create_client(self, client):
        clt = None
        cid = client['id']
        if client['type'] == 'deproxy':
            clt = self.__create_client_deproxy(client)
        elif client['type'] == 'wrk':
            clt = self.__create_client_wrk(client)
        self.__clients[cid] = clt

    def __create_srv_nginx(self, server):
        srv = Nginx()
        for lst in server['servers']:
            ip = lst['ip']
            port = lst['port']
            if port == 'default':
                port = tempesta.upstream_port_start_from()
            else:
                port = int(port)

            if ip == 'default':
                ip = tf_cfg.cfg.get('Server', 'ip')
            sid = lst['id']
            if lst.has_key('location'):
                location = lst['location']
                srv.config.add_server_location(ip_listen=ip,
                                               port=port,
                                               location=location,
                                               id=sid)
            elif lst.has_key('code'):
                code = int(lst['code'])
                srv.config.add_server_code(ip_listen=ip,
                                           port=port,
                                           code=code,
                                           id=sid)
        return srv

    def __create_srv_deproxy(self, server):
        port = server['port']
        if port == 'default':
            port = tempesta.upstream_port_start_from()
        else:
            port = int(port)

        srv = deproxy.Server(port=port)
        return srv

    def __create_backend(self, server):
        srv = None
        sid = server['id']
        if server['type'] == 'nginx':
            srv = self.__create_srv_nginx(server)
        elif server['type'] == 'deproxy':
            srv = self.__create_srv_deproxy(server)
        self.__servers[sid] = srv

    def __create_servers(self):
        for server in self.backends:
            self.__create_backend(server)

    def get_server(self, sid):
        """ Return client with specified id """
        if not self.__servers.has_key(sid):
            return None
        return self.__servers[sid]

    def get_servers_id(self):
        """ Return list of registered servers id """
        return self.__servers.keys()

    def __create_clients(self):
        for client in self.clients:
            self.__create_client(client)

    def get_client(self, cid):
        """ Return client with specified id """
        if not self.__clients.has_key(cid):
            return None
        return self.__clients[cid]
    
    def get_clients_id(self):
        """ Return list of registered clients id """
        return self.__clients.keys()

    def get_tempesta(self):
        """ Return Tempesta instance """
        return self.__tempesta

    def __create_tempesta(self):
        config = ""
        if self.tempesta.has_key('config'):
            config = self.tempesta['config']
        self.__tempesta = control.Tempesta()
        self.__tempesta.config.set_defconfig(config)

    def start_all_servers(self):
        for srv in self.__servers:
            srv.start()
            if srv.state != stateful.STATE_STARTED:
                raise Exception("Can not start server")

    def start_tempesta(self):
        self.__tempesta.start()
        if self.__tempesta.state != stateful.STATE_STARTED:
            raise Exception("Can not start Tempesta")

    def start_all_clients(self):
        for client in self.__clients:
            client.start()
            if client.state != stateful.STATE_STARTED:
                raise Exception("Can not start client")

    def setUp(self):
        tf_cfg.dbg(3, '\tInit test case...')
        self.__create_servers()
        self.__create_tempesta()
        self.__create_clients()

    def tearDown(self):
        for client in self.__clients:
            client.stop()
        self.__tempesta.stop()
        for server in self.__servers:
            server.stop()
        try:
            deproxy.finish_all_deproxy()
        except:
            print ('Unknown exception in stopping deproxy')
