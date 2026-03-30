# Changelog

All notable changes to the getdc project will be documented in this file.

## [Unreleased] - 2026-03-30

### Added - Configurable Timeout Parameters

#### Summary
Added configurable timeout parameters for DNS and LDAP operations to allow users to control network operation timeouts based on their requirements.

#### Changes Made
- Added `dns_timeout` parameter to `DCert.__init__()` (default: 5.0 seconds)
- Added `ldap_timeout` parameter to `DCert.__init__()` (default: 10.0 seconds)
- Updated all DNS resolver calls to use configurable timeout via `resolver.lifetime`
- Updated all LDAP connection calls to use configurable timeout via `ldap.OPT_NETWORK_TIMEOUT`

#### Usage
```python
from gdc import get_direct_certificate

# Use default timeouts (DNS: 5s, LDAP: 10s)
dc = DCert('example.com')

# Custom timeouts
dc = DCert('example.com', dns_timeout=10.0, ldap_timeout=20.0)

# Faster timeouts for quick checks
dc = DCert('example.com', dns_timeout=2.0, ldap_timeout=5.0)
```

#### Affected Methods
- `validate_certificate_dns()` - Uses `dns_timeout`
- `validate_certificate_ldap()` - Uses both `dns_timeout` (for SRV lookup) and `ldap_timeout`
- `get_certificate_dns()` - Uses `dns_timeout`
- `get_certificate_ldap()` - Uses both `dns_timeout` (for SRV lookup) and `ldap_timeout`

### Fixed - Python 3.11+ Compatibility

#### Summary
Fixed all `base64.encodestring()` usage which was deprecated in Python 3.1 and removed in Python 3.9. The code now uses `base64.encodebytes()` with proper `.decode('utf-8')` calls to ensure compatibility with Python 3.11 and above.

#### Technical Details

**Problem:** 
- `base64.encodestring()` was removed in Python 3.9
- `base64.encodebytes()` returns bytes, not strings, requiring explicit decoding for string operations
- Without proper decoding, certificate strings couldn't be concatenated or written to files correctly

**Solution:**
Replaced all instances of:
```python
base64.encodestring(data).rstrip()
```

With:
```python
base64.encodebytes(data).rstrip().decode('utf-8')
```

#### Files Modified

1. **gdc/get_direct_certificate.py**
   - Line ~179: `validate_certificate_dns()` - Fixed DNS certificate download and cert_string creation
   - Line ~193: `validate_certificate_dns()` - Fixed cert_string for certificate parsing
   - Line ~363-366: `validate_certificate_ldap()` - Fixed LDAP certificate file writing and cert_string creation
   - Line ~406-408: `get_certificate_dns()` - Fixed DNS certificate file writing and response concatenation
   - Line ~459-463: `get_certificate_ldap()` - Fixed LDAP certificate file writing and response concatenation

2. **setup.py**
   - Added `python_requires='>=3.11'` to explicitly declare minimum Python version requirement

3. **tests/test_base64_compatibility.py** (New)
   - Added comprehensive tests to verify base64 encoding compatibility
   - Tests verify that encodebytes + decode pattern works correctly
   - Tests verify roundtrip encoding/decoding
   - Tests document that encodestring is not available in Python 3.9+

#### Testing
- All base64 compatibility tests pass (3/3 tests)
- Changes are backwards compatible with Python 3.11+
- No functionality changes - only compatibility fixes

#### Backwards Compatibility
✅ **Python 3.11+**: Fully compatible  
✅ **Python 3.12+**: Fully compatible  
✅ **Python 3.13+**: Fully compatible  
✅ **Python 3.14+**: Fully compatible  
❌ **Python 3.8 and below**: Not compatible (base64.encodestring still existed but was deprecated)

### Changed
- Updated `setup.py` to explicitly require Python 3.11 or higher

### Added
- Created `tests/test_base64_compatibility.py` to verify Python 3.11+ compatibility
- Added explicit Python version requirement in setup.py

---

## [0.2.3] - Previous Release

See git history for details of previous releases.
