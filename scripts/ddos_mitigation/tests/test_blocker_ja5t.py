import unittest
import os

from blockers.base import PreperationError
from blockers.ja5t import Ja5tBlocker
from ja5_config import Ja5Config, Ja5Hash
from datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestBlockerJa5t(unittest.TestCase):
    def setUp(self):
        self.config_path = '/tmp/test_ja5t_config'
        self.blocker = Ja5tBlocker(Ja5Config(self.config_path))
        open(self.config_path, 'w').close()

    def tearDown(self):
        os.remove(self.config_path)

    def test_load(self):
        with open(self.config_path, 'w') as f:
            f.write('hash 1111 0 0;\nhash 2222 0 0;\n')

        users = self.blocker.load()
        self.assertEqual(len(users), 2)
        self.assertEqual(users[0].ja5t, '1111')
        self.assertEqual(users[1].ja5t, '2222')

    def test_block(self):
        user = User(ja5t='11111')
        self.blocker.block(user)
        self.assertEqual(len(self.blocker.config.hashes), 1)
        self.assertEqual(self.blocker.config.hashes['11111'].value, '11111')

    def test_release(self):
        user = User(ja5t='3333')
        self.blocker.config.hashes['3333'] = Ja5Hash(value='3333', connections=0, packets=0)
        self.blocker.release(user)
        self.assertEqual(len(self.blocker.config.hashes), 0)

    def test_apply(self):
        self.blocker.block(User(ja5t='11111'))
        self.blocker.apply()

        with open(self.config_path, 'r') as f:
            data = f.read()

        self.assertEqual(data, 'hash 11111 0 0;\n')

    def test_info(self):
        self.blocker.block(User(ja5t='11111'))
        users = self.blocker.info()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].ja5t, '11111')

    def test_prepare_no_tempesta_service(self):
        with self.assertRaises(PreperationError) as e:
            self.blocker.prepare()
            self.assertIn('executable not found', str(e.exception))

    def test_prepare_no_config(self):
        self.blocker.tempesta_executable_path = '/tmp/path'
        open(self.config_path, 'w').close()

        with self.assertRaises(PreperationError) as e:
            self.blocker.prepare()
            self.assertIn('file not found', str(e.exception))
