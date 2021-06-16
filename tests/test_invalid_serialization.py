# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""" Unit tests testing invalid serialization cases for
tuf/api/metadata.py classes.
"""

import json
import sys
import logging
import unittest
import copy

from datetime import datetime
from typing import Any, Dict, Callable, Type, Optional, Mapping

from tests import utils

from tuf.api.metadata import (
    Signed
)

logger = logging.getLogger(__name__)

# DataSet is only here so type hints can be used:
# It is a dict of name to test dict
DataSet = Dict[str, Dict[str, str]]

# Test runner decorator: Runs the test as a set of N SubTests,
# (where N is number of items in dataset), feeding the actual test
# function one test case at a time
def run_sub_tests_with_dataset(dataset: Type[DataSet]):
    def real_decorator(function: Callable[["TestInvalidSerialization", DataSet], None]):
        def wrapper(test_cls: "TestInvalidSerialization"):
            for attr_cases in dataset.values():
              for case, data in attr_cases.items():
                  with test_cls.subTest(case=case):
                      function(test_cls, data)
        return wrapper
    return real_decorator

class TestSigned(Signed):
    """Used for testing the abstract "Signed" class."""

    _signed_type = "signed"

    def __init__(
        self,
        version: int,
        spec_version: str,
        expires: datetime,
        unrecognized_fields: Optional[Mapping[str, Any]]
    ) -> None:
        super().__init__(
            version, spec_version, expires, unrecognized_fields
        )

    @classmethod
    def from_dict(cls, signed_dict: Dict[str, Any]) -> "Signed":
        common_args = super()._common_fields_from_dict(signed_dict)
        # All fields left in the signed_dict are unrecognized.
        return cls(*common_args, signed_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dict representation of self."""
        return super()._common_fields_to_dict()


class TestInvalidSerialization(unittest.TestCase):

    invalid_singed : DataSet = {
        "invalid _type": {
            "no _type": '{"spec_version": "1.0.0", "expires": "2030-01-01T00:00:00Z"}',
            "empty str _type": '{"_type": "", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "wrong _type": '{"_type": "foo", "spec_version": "1.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z"}'
        },
        "invalid spec_version": {
            "no spec_version": '{"_type": "signed", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "empty str spec_version": '{"_type": "signed", "spec_version": "", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "invalid spec_version str": '{"_type": "signed", "spec_version": "abc", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "one digit spec_version": '{"_type": "signed", "spec_version": "1", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "two digit spec_version": '{"_type": "signed", "spec_version": "1.2", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "no digit spec_version": '{"_type": "signed", "spec_version": "a.b.c", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
            "different major spec_version": '{"_type": "signed", "spec_version": "0.0.0", "version": 1, "expires": "2030-01-01T00:00:00Z"}',
        },
        "invalid version": {
            "no version": '{"_type": "signed", "spec_version": "1.0.0", "expires": "2030-01-01T00:00:00Z"}',
            "version 0": '{"_type": "signed", "spec_version": "1.0.0", "version": 0, "expires": "2030-01-01T00:00:00Z"}',
            "version below 0": '{"_type": "signed", "spec_version": "1.0.0", "version": -1, "expires": "2030-01-01T00:00:00Z"}'
        },
        "invalid expires": {
            "no expires": '{"_type": "signed", "spec_version": "1.0.0", "version": 1}',
            "wrong datetime string": '{"_type": "signed", "spec_version": "1.0.0", "version": 1, "expires": "abc"}'
        }
    }

    @run_sub_tests_with_dataset(invalid_singed)
    def test_invalid_signed_attr(self, test_case_data: Dict[str, str]):
        case_dict = json.loads(test_case_data)
        with self.assertRaises((KeyError, ValueError)):
            TestSigned.from_dict(copy.copy(case_dict))


# Run unit test.
if __name__ == '__main__':
    utils.configure_test_logging(sys.argv)
    unittest.main()
