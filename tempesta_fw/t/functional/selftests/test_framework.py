from helpers import chains
from testers import common

class ExampleTestNginx(common.TempestaTest):
    backends = [
        {
            'id' : 'default_id',
            'type' : 'nginx',
            'request_connections' : 200,
            'servers' : [
                {
                    'ip' : 'default',
                    'port' : 8000,
                    'location' : '/var/www/html',
                }
            ]
        }
    ]

    tempesta = {   
        'listen_ip' : 'default',
        'listen_port' : 80,
        'backends' : ['default_id'],
    }

    clients = [
        {
            'id' : 'default_id',
            'type' : 'deproxy',
        }
    ]

    def test(self):
        """ Simple test """
        chain = chains.base(uri = "/path", method = "GET")

class ExampleTestDeproxy(common.TempestaTest):
    backends = [
        {
            'id' : 'default_id',
            'type' : 'deproxy',
            'port' : 'default',
        }
    ]

    tempesta = {   
        'listen_ip' : 'default',
        'listen_port' : 80,
        'backends' : ['default_id'],
    }

    clients = [
        {
            'id' : 'default_id',
            'type' : 'deproxy',
        }
    ]

    def test(self):
        """ Simple test """
        chain = chains.base(uri = "/path", method = "GET")
