import os
import unittest
from system_verification import Config
from typing import Optional


class TestCorrectValues(unittest.TestCase):

    def setUp(self):
        self.config_path = '/tmp/t-config'

        with open(self.config_path, 'w') as f:
            f.write('\n'.join(self.get_config()))

        self.parsed_config = Config(self.config_path)

    def tearDown(self):
        os.remove(self.config_path)

    def get_config(self) -> list[str]:
        return [
            'kernel.a=1',
            'kernel.b = 1',
            'kernel.panic   =     1    ',
            '   kernel.group_panic   =   y   ',
            'extra   =   no   ',
            '# commented=y',
            '### # line = y',

            '# oneline=1',
            'oneline=1',

            '# secondline=1',
            'secondline=1',
            '# secondline=1',
        ]

    def test_simple(self):
        self.assertTrue(self.parsed_config.check_params_are_same({
            'kernel.a': {'0', '1'},
        }))

    def test_value_with_spaces_around_equal(self):
        self.assertTrue(self.parsed_config.check_params_are_same({
            'kernel.b': {'1'},
        }))

    def test_value_with_spaces_around_all_except_start(self):
        self.assertTrue(self.parsed_config.check_params_are_same({
            'kernel.panic': {'1'},
        }))

    def test_spaces_anywhere(self):
        self.assertTrue(self.parsed_config.check_params_are_same({
            'kernel.group_panic': {'y'},
        }))

    def test_key_with_one_word(self):
        self.assertTrue(self.parsed_config.check_params_are_same({
            'extra': {'no'},
        }))

    def test_correct_comment(self):
        test_config = Config(self.config_path)
        self.assertFalse(test_config.check_params_are_same({
            'commented': {'y'},
        }))

    def test_multiple_sharps(self):
        test_config = Config(self.config_path)
        self.assertFalse(test_config.check_params_are_same({
            'line': {'y'},
        }))

    def test_optional_param(self):
        test_config = Config(self.config_path)
        self.assertTrue(test_config.check_params_are_same({
            'default_param': {Optional, 'y'},
        }))

    def test_line_after_comment(self):
        test_config = Config(self.config_path)
        self.assertTrue(test_config.check_params_are_same({
            'oneline': {'1'},
        }))

    def test_line_in_middle_of_comment(self):
        test_config = Config(self.config_path)
        self.assertTrue(test_config.check_params_are_same({
            'secondline': {'1'},
        }))


if __name__ == '__main__':
    unittest.main()
