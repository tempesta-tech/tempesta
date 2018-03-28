class ExampleTest(object):
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
            'type' : 'deproxy',
            'request_message' : "GET /uri HTTP/1.1\r\nHost: localhost\r\n\r\n",
            'expected_response_code' : "404",
            'expected_response_body' : '',
            'expected_response_headers' : {
                'Content-Length' : '0',
                'Server' : 'Tempesta FW/0.5.0',
            }
        }
    ]
