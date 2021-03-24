import inspect
from abc import ABC, abstractmethod
from datetime import datetime, timedelta


class Validator(ABC):
    def __set_name__(self, owner, name):
        self.private_name = "_" + "NO_VALIDATION_" + name

    def __get__(self, obj, objtype=None):
        return getattr(obj, self.private_name)

    def __set__(self, obj, value):
        self.validate(value)
        setattr(obj, self.private_name, value)

    @abstractmethod
    def validate(self, value):
        pass


class OneOf(Validator):
    def __init__(self, *options):
        self.options = set(options)

    def validate(self, value):
        if value not in self.options:
            raise ValueError(
                f"Expected {value!r} to be one of {self.options!r}"
            )


class Integer(Validator):
    def __init__(self, minvalue=None, maxvalue=None):
        self.minvalue = minvalue
        self.maxvalue = maxvalue

    def validate(self, value):
        if not isinstance(value, int):
            raise TypeError(f"Expected {value!r} to be an int or float")
        if self.minvalue is not None and value < self.minvalue:
            raise ValueError(
                f"Expected {value!r} to be at least {self.minvalue!r}"
            )
        if self.maxvalue is not None and value > self.maxvalue:
            raise ValueError(
                f"Expected {value!r} to be no more than {self.maxvalue!r}"
            )


class String(Validator):
    def __init__(self, minsize=None, maxsize=None, predicate=None):
        self.minsize = minsize
        self.maxsize = maxsize

        # This can be whatever predicate function we want until it returns
        # a boolean value.
        self.predicate = predicate

    def validate(self, value):
        if not isinstance(value, str):
            raise TypeError(f"Expected {value!r} to be an str")
        if self.minsize is not None and len(value) < self.minsize:
            raise ValueError(
                f"Expected {value!r} to be no smaller than {self.minsize!r}"
            )
        if self.maxsize is not None and len(value) > self.maxsize:
            raise ValueError(
                f"Expected {value!r} to be no bigger than {self.maxsize!r}"
            )
        if self.predicate is not None and not self.predicate(value):
            raise ValueError(
                f"Expected {self.predicate} to be true for {value!r}"
            )


class DateTime(Validator):

    def validate(self, value):
        if not isinstance(value, datetime):
            raise TypeError(
                f"Expected {value} to be a datetime.datetime object!"
            )
