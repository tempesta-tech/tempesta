from helpers import chains
from testers import common

class ExampleTestNginx(common.TempestaTest):
    backends = [
        {
            'id' : 'default_backend',
            'type' : 'nginx',
            'keepalive_requests' : 200,
            'servers' : [
                {
                    'id' : 'default_server',
                    'ip' : 'default',
                    'port' : 8000,
                    'location' : '/var/www/html',
                }
            ]
        }
    ]

    tempesta = {
        'config' : 'cache 0;\n',
        'listen_ip' : 'default',
        'listen_port' : 80,
        'groups' : [
            {
                'name' : 'default',
                'backends' : [
                    {
                        'backend' : 'default_backend',
                        'port' : 'default_server',
                    }
                ],
            }
        ],
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
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

class ExampleTestDeproxy(common.TempestaTest):
    backends = [
        {
            'id' : 'default_backend',
            'type' : 'deproxy',
            'port' : 'default',
        }
    ]

    tempesta = {   
        'listen_ip' : 'default',
        'listen_port' : 80,
        'groups' : [
            {
                'name' : 'default',
                'backends' : [
                    {'backend' : 'default_backend'}
                ],
            }
        ],
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
