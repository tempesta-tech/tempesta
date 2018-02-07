from helpers import control, tempesta, tf_cfg
from testers import stress

import mixed_test

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class GetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "pipeline"
    pipelined_req = 7

class RealRequest(mixed_test.MixedRequests):
    """ Real GET request """
    script = "get_real"
    pipelined_req = 1

class RealRequest2(mixed_test.MixedRequests):
    """ Real GET request 2"""
    script = "get_real_2"
    pipelined_req = 1

class RealRequestPipeline(mixed_test.MixedRequests):
    """ Real pipelined GET request """
    script = "get_real_pipelined"
    pipelined_req = 3

class GetPostRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "get_post"
    pipelined_req = 5

class HeadGetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "head_get"
    pipelined_req = 2

class EmptyPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_empty"
    pipelined_req = 1

class SmallPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_small"
    pipelined_req = 1

class BigPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_big"
    pipelined_req = 1

class RarelyUsedRequests(mixed_test.MixedRequests):
    """ Rarely used requests """
    script = "mixed"
    pipelined_req = 9
