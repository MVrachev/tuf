"""Provides classes used for validation. """

import inspect



class ValidationMixin(object):
  """Provides a validate method to allow tuf objects to validate their fields.

  The validation mixin provides a self-inspecting method, validate, to
  allow in-toto's objects to check that they are proper. """

  def validate(self):
    """Validates attributes of the instance.

    Raises:
      securesystemslib.formats.FormatError: An attribute value is invalid.
    """
    for method in inspect.getmembers(self, predicate=inspect.ismethod):
      if method[0].startswith("_validate_"):
        method[1]()
