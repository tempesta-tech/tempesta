import os
import unittest

from ja5_config import Ja5Config, Ja5Hash


class TestJa5Config(unittest.TestCase):
    def setUp(self):
        self.path_to_file_wrong_permissions = '/tmp/wrong_permissions'
        self.path_to_config = '/tmp/tmp-hashes'

        with open(self.path_to_file_wrong_permissions, 'w') as f:
            f.write('')

        os.chmod(self.path_to_file_wrong_permissions, 0o000)

        with open(self.path_to_config, 'w') as f:
            f.write(
                'aaaaaaa11111 3 4;\n'
                '  2222aaaaaaa 12   23444  ;  \n'
                '  wrong222 12   ;  \n'
                '  wrong-again  ;  \n'
                '#commented  ;  \n'
            )

    def tearDown(self):
        os.chmod(self.path_to_file_wrong_permissions, 0o777)
        os.remove(self.path_to_file_wrong_permissions)
        os.remove(self.path_to_config)

    def test_config_does_not_exists(self):
        with self.assertRaises(FileNotFoundError):
            Ja5Config('/tmp/non-existing.conf')

    def test_config_does_not_have_permissions(self):
        with self.assertRaises(PermissionError):
            Ja5Config(self.path_to_file_wrong_permissions)

    def test_load_hashes_from_file(self):
        config = Ja5Config(self.path_to_config)
        self.assertEqual(len(config.hashes), 2)

    def test_dump_file(self):
        config = Ja5Config(self.path_to_config)
        config.hashes = {
            'test': Ja5Hash(value='test', connections=1, packets=1)
        }
        config.dump()

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, 'test 1 1;\n')

    def test_modification(self):
        config = Ja5Config(self.path_to_config)
        self.assertEqual(config.need_dump, False)

        config.add(Ja5Hash(value=100, connections=1, packets=2))
        self.assertEqual(config.need_dump, True)

        config.dump()
        self.assertEqual(config.need_dump, False)

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, 'aaaaaaa11111 3 4;\n2222aaaaaaa 12 23444;\n100 1 2;\n')

        config.remove(100)
        self.assertEqual(config.need_dump, True)

        config.dump()
        self.assertEqual(config.need_dump, False)

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, 'aaaaaaa11111 3 4;\n2222aaaaaaa 12 23444;\n')
