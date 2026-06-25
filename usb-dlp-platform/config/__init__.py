"""
Configuration package for the Secure USB DLP System.

Exposes a single, process-wide `settings` object (see settings.py) that
every other module imports from rather than re-reading environment
variables independently. This keeps configuration centralized and
testable.
"""

from config.settings import settings  # noqa: F401
