"""Shared test configuration.

The backend modules live one directory up and are imported by module name
(`import scan_import`), matching how the application itself imports them, so the
package root goes on sys.path here rather than in each test file.
"""
import os
import sys

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)
