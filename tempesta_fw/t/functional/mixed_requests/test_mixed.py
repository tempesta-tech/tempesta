from helpers import control, tempesta, tf_cfg
from testers import stress

import mixed_test

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class GetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "pipeline"

class GetPostRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "get_post"

class HeadGetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "head_get"

class SmallPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_small"

class BigPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_big"

class RarelyUsedRequests(mixed_test.MixedRequests):
    """ Rarely used requests """
    script = "mixed"
