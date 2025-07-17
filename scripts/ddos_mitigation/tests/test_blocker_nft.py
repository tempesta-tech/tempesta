from blockers.nft import NFTBlocker
from tests.test_blocker_ipset import TestBlockerIpSet

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestBlockerNFT(TestBlockerIpSet):
    def setUp(self):
        self.blocker = NFTBlocker(blocking_table_name='tempesta_blocked_ips')
        self.blocker.prepare()
