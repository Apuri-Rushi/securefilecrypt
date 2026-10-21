"""
Test runner capable of executing tests with standard unittest or pytest.
"""

import sys
from pathlib import Path

# Ensure workspace root is in sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    try:
        import pytest
        sys.exit(pytest.main(["baseline/tests", "-v"]))
    except ImportError:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover("baseline/tests", pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)
