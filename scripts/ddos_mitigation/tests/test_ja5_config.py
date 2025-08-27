import os
import unittest

from utils.ja5_config import Ja5Config, Ja5Hash

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestJa5Config(unittest.TestCase):
    def setUp(self):
        self.path_to_config = "/tmp/tmp-hashes"

        with open(self.path_to_config, "w") as f:
            f.write(
                "hash aaaaaaa11111 3 4;\n"
                "  2222aaaaaaa 12   23444  ;  \n"
                " hash wrong222 12   ;  \n"
                "  hash wrong-again  ;  \n"
                "#commented  ;  \n"
            )

    def tearDown(self):
        os.remove(self.path_to_config)

    def test_config_does_not_exists(self):
        with self.assertRaises(FileNotFoundError):
            config = Ja5Config("/tmp/non-existing.conf")
            config.verify_file()

    def test_load_hashes_from_file(self):
        config = Ja5Config(self.path_to_config)
        config.load()

        self.assertEqual(len(config.hashes), 1)

    def test_dump_file(self):
        config = Ja5Config(self.path_to_config)
        config.load()

        config.hashes = {"test": Ja5Hash(value="0", connections=1, packets=1)}
        config.dump()

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, "hash 0 1 1;\n")

    def test_modification(self):
        config = Ja5Config(self.path_to_config)
        config.load()
        self.assertEqual(config.need_dump, False)

        config.add(Ja5Hash(value="100", connections=1, packets=2))
        self.assertEqual(config.need_dump, True)

        config.dump()
        self.assertEqual(config.need_dump, False)

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, "hash aaaaaaa11111 3 4;\nhash 100 1 2;\n")

        config.remove("100")
        self.assertEqual(config.need_dump, True)

        config.dump()
        self.assertEqual(config.need_dump, False)

        with open(self.path_to_config) as f:
            data = f.read()

        self.assertEqual(data, "hash aaaaaaa11111 3 4;\n")
