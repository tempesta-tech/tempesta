from helpers import control, tempesta, tf_cfg
from testers import stress

class MixedRequests(stress.StressTest):
    """ Mixed requests test """
    config = 'cache 0;\n'
    script = None
    def create_clients(self):
        self.wrk = control.Wrk(threads=8)
        self.wrk.set_script(self.script)
        self.clients = [self.wrk]

    def test(self):
        """ Run mixed requests test """
        self.generic_test_routine(self.config)
