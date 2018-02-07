from helpers import control, tempesta, tf_cfg
from testers import stress

class MixedRequests(stress.StressTest):
    """ Mixed requests test """
    config = 'cache 0;\n'
    script = None
    clients_num = int(tf_cfg.cfg.get('General', 'concurrent_connections'))

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port, code=200)]

    def create_clients(self):
        self.wrk = control.Wrk(threads=self.clients_num)
        self.wrk.set_script(self.script)
        self.clients = [self.wrk]

    def test(self):
        """ Run mixed requests test """
        self.generic_test_routine(self.config)
