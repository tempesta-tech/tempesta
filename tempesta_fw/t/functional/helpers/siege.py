from __future__ import print_function

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Config(object):
    """ Siege.rc file helper.

    Most of siege options require to update file and cannot be changed using
    command-line arguments.
    """

    def __init__(self):
        self.filename = 'siege.rc'
        self.options = [
            # Default concurrent.
            ('concurrent', '25'),
            # Disable printing eash transaction to stdout.
            ('verbose', 'false'),
            # Leave color for humas. It breaks regexes.
            ('color', 'off'),
            ('protocol', 'HTTP/1.1'),
            ('quiet', 'false'),
            ('show-logfile', 'false'),
            ('logging', 'false'),
            ('accept-encoding', 'gzip;deflate'),
            # Cache revalidation.
            ('cache', 'false'),
            # Method used, when running with `-g` option.
            ('gmethod', 'HEAD'),
            # Enable http parser.
            ('parser', 'true'),
            # Cookies support.
            ('cookies', 'true'),
            # Number of total failures allowed before siege aborts.
            ('failures', '10'),
            # Keep-Alive or close connections after each request.
            ('connection', 'close')]

    def set_option(self, option, value):
        for i in range(len(self.options)):
            opt, _ = self.options[i]
            if opt == option:
                if value == '':
                    del self.options[i]
                else:
                    self.options[i] = (option, value)
                return
        if value:
            self.options.append((option, value))


    def get_config(self):
        cfg = '\n'.join(['%s = %s' % opt for opt in self.options])
        return cfg
