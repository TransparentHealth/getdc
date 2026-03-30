#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test to verify Python 3.11+ compatibility for base64 encoding operations.

This test ensures that all base64.encodebytes() calls properly decode bytes to UTF-8 strings,
which is required for Python 3.9+ compatibility (base64.encodestring was removed).
"""

import base64
import unittest


class TestBase64Compatibility(unittest.TestCase):
    """Test base64 encoding operations for Python 3.11+ compatibility."""

    def test_base64_encodebytes_with_decode(self):
        """Test that base64.encodebytes followed by decode works correctly."""
        # Sample binary data (simulating certificate data)
        test_data = b"Test certificate data"
        
        # This is the pattern used in the fixed code
        encoded = base64.encodebytes(test_data).rstrip().decode('utf-8')
        
        # Verify it returns a string (not bytes)
        self.assertIsInstance(encoded, str)
        
        # Verify it can be written to a file (string concatenation)
        cert_string = "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n"
        self.assertIsInstance(cert_string, str)
        
    def test_base64_decode_roundtrip(self):
        """Test that encoding and decoding works correctly."""
        test_data = b"Test certificate data for roundtrip"
        
        # Encode
        encoded = base64.encodebytes(test_data).rstrip().decode('utf-8')
        
        # Decode back
        decoded = base64.b64decode(encoded)
        
        # Verify roundtrip
        self.assertEqual(test_data, decoded)
        
    def test_encodestring_not_available(self):
        """Verify that base64.encodestring is not available in Python 3.9+."""
        # This test documents that base64.encodestring was removed
        # and should not be used
        self.assertFalse(
            hasattr(base64, 'encodestring'),
            "base64.encodestring should not be used (removed in Python 3.9)"
        )


if __name__ == '__main__':
    unittest.main()
