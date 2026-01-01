# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Evasion configuration module for protocol legitimacy
#   Provides Windows-like protocol behavior profiles for authorized
#   security testing and research purposes.
#
# Author:
#   Security Research Configuration Module
#

import os
import secrets
import struct
import uuid as uuid_module
from datetime import datetime, timezone, timedelta

# ============================================================================
# EVASION PROFILE CONFIGURATION
# ============================================================================
# This module provides configuration options to make Impacket traffic
# appear more like legitimate Windows client traffic.
#
# Profiles available:
#   - DEFAULT: Original Impacket behavior (for backward compatibility)
#   - WINDOWS_11: Windows 11 22H2+ behavior
#   - WINDOWS_10: Windows 10 21H2 behavior
#   - WINDOWS_SERVER_2022: Windows Server 2022 behavior
# ============================================================================

class EvasionProfile:
    """Base class for evasion profiles"""

    # Profile identifier
    PROFILE_NAME = "DEFAULT"

    # ========================================================================
    # NTLM Configuration
    # ========================================================================

    # OS Version information for NTLM VERSION structure
    NTLM_PRODUCT_MAJOR_VERSION = 0
    NTLM_PRODUCT_MINOR_VERSION = 0
    NTLM_PRODUCT_BUILD = 0
    NTLM_REVISION = 0x0F  # NTLMSSP_REVISION_W2K3

    # Workstation name behavior
    NTLM_INCLUDE_WORKSTATION = False
    NTLM_WORKSTATION_PREFIX = ""

    # Use cryptographically secure random for challenges
    NTLM_USE_SECURE_RANDOM = False

    # ========================================================================
    # Kerberos Configuration
    # ========================================================================

    # KDC Options for AS-REQ
    KRB_AS_REQ_FLAGS = ['forwardable', 'renewable', 'proxiable']

    # KDC Options for TGS-REQ
    KRB_TGS_REQ_FLAGS = ['forwardable', 'renewable', 'renewable_ok', 'canonicalize']

    # Encryption type preference order for TGS-REQ
    KRB_TGS_ETYPE_ORDER = ['rc4_hmac', 'des3_cbc_sha1_kd', 'des_cbc_md5']

    # Nonce bit size (Windows uses 32-bit)
    KRB_NONCE_BITS = 31

    # Ticket validity period in hours
    KRB_TICKET_VALIDITY_HOURS = 24

    # GSS-API checksum flags
    KRB_GSS_FLAGS = 0x103E  # All flags

    # ========================================================================
    # SMB Configuration
    # ========================================================================

    # Use proper UUID format for ClientGuid
    SMB_USE_PROPER_GUID = False

    # Default capabilities
    SMB_CAPABILITIES = 0x40  # Encryption only

    # Include SMB 3.1.1 in dialect negotiation
    SMB_INCLUDE_311 = False

    # Default security mode
    SMB_SECURITY_MODE = 0x01  # Signing enabled

    # Credit request pattern
    SMB_CREDIT_REQUEST = 127
    SMB_CREDIT_THRESHOLD = 3

    # Use secure random for nonces/salts
    SMB_USE_SECURE_RANDOM = False

    # ========================================================================
    # DCE/RPC Configuration
    # ========================================================================

    # Fragment sizes
    RPC_MAX_FRAGMENT_SIZE = 4280

    # Auth context ID offset
    RPC_AUTH_CTX_ID_OFFSET = 79231

    # SEC_TRAILER auth_ctx_id
    RPC_SEC_TRAILER_AUTH_CTX_ID = 747920

    # Randomize call ID
    RPC_RANDOMIZE_CALL_ID = False


class Windows11Profile(EvasionProfile):
    """Windows 11 22H2+ behavior profile"""

    PROFILE_NAME = "WINDOWS_11"

    # ========================================================================
    # NTLM Configuration - Windows 11 22H2
    # ========================================================================

    # Windows 11 22H2 version info
    NTLM_PRODUCT_MAJOR_VERSION = 10
    NTLM_PRODUCT_MINOR_VERSION = 0
    NTLM_PRODUCT_BUILD = 22621  # Windows 11 22H2
    NTLM_REVISION = 0x0F

    # Include workstation name like Windows does
    NTLM_INCLUDE_WORKSTATION = True
    NTLM_WORKSTATION_PREFIX = "DESKTOP-"

    # Use cryptographically secure random
    NTLM_USE_SECURE_RANDOM = True

    # ========================================================================
    # Kerberos Configuration - Windows 11
    # ========================================================================

    # Windows 11 typically uses fewer flags
    KRB_AS_REQ_FLAGS = ['forwardable', 'renewable']

    # TGS-REQ flags
    KRB_TGS_REQ_FLAGS = ['forwardable', 'renewable', 'canonicalize']

    # Windows 11 prefers AES, then RC4
    KRB_TGS_ETYPE_ORDER = ['aes256_cts_hmac_sha1_96', 'aes128_cts_hmac_sha1_96', 'rc4_hmac']

    # 32-bit nonce like Windows
    KRB_NONCE_BITS = 32

    # Windows typically uses 10-hour tickets
    KRB_TICKET_VALIDITY_HOURS = 10

    # More conservative GSS flags
    KRB_GSS_FLAGS = 0x201E  # MUTUAL | REPLAY | SEQUENCE | CONF | INTEG

    # ========================================================================
    # SMB Configuration - Windows 11
    # ========================================================================

    # Use proper UUID format
    SMB_USE_PROPER_GUID = True

    # Windows 11 capabilities - more comprehensive
    SMB_CAPABILITIES = 0x7F  # All standard capabilities

    # Include SMB 3.1.1
    SMB_INCLUDE_311 = True

    # Require signing
    SMB_SECURITY_MODE = 0x03  # Signing enabled + required

    # Gradual credit increase
    SMB_CREDIT_REQUEST = 64
    SMB_CREDIT_THRESHOLD = 1

    # Use secure random
    SMB_USE_SECURE_RANDOM = True

    # ========================================================================
    # DCE/RPC Configuration - Windows 11
    # ========================================================================

    # Standard Windows fragment size
    RPC_MAX_FRAGMENT_SIZE = 5840

    # Randomized auth context
    RPC_AUTH_CTX_ID_OFFSET = None  # Will be randomized

    # Randomized SEC_TRAILER
    RPC_SEC_TRAILER_AUTH_CTX_ID = None  # Will be randomized

    # Randomize call ID
    RPC_RANDOMIZE_CALL_ID = True


class Windows10Profile(EvasionProfile):
    """Windows 10 21H2 behavior profile"""

    PROFILE_NAME = "WINDOWS_10"

    # ========================================================================
    # NTLM Configuration - Windows 10 21H2
    # ========================================================================

    NTLM_PRODUCT_MAJOR_VERSION = 10
    NTLM_PRODUCT_MINOR_VERSION = 0
    NTLM_PRODUCT_BUILD = 19044  # Windows 10 21H2
    NTLM_REVISION = 0x0F

    NTLM_INCLUDE_WORKSTATION = True
    NTLM_WORKSTATION_PREFIX = "DESKTOP-"

    NTLM_USE_SECURE_RANDOM = True

    # ========================================================================
    # Kerberos Configuration - Windows 10
    # ========================================================================

    KRB_AS_REQ_FLAGS = ['forwardable', 'renewable']
    KRB_TGS_REQ_FLAGS = ['forwardable', 'renewable', 'canonicalize']
    KRB_TGS_ETYPE_ORDER = ['aes256_cts_hmac_sha1_96', 'aes128_cts_hmac_sha1_96', 'rc4_hmac']
    KRB_NONCE_BITS = 32
    KRB_TICKET_VALIDITY_HOURS = 10
    KRB_GSS_FLAGS = 0x201E

    # ========================================================================
    # SMB Configuration - Windows 10
    # ========================================================================

    SMB_USE_PROPER_GUID = True
    SMB_CAPABILITIES = 0x7F
    SMB_INCLUDE_311 = True
    SMB_SECURITY_MODE = 0x01
    SMB_CREDIT_REQUEST = 64
    SMB_CREDIT_THRESHOLD = 1
    SMB_USE_SECURE_RANDOM = True

    # ========================================================================
    # DCE/RPC Configuration - Windows 10
    # ========================================================================

    RPC_MAX_FRAGMENT_SIZE = 5840
    RPC_AUTH_CTX_ID_OFFSET = None
    RPC_SEC_TRAILER_AUTH_CTX_ID = None
    RPC_RANDOMIZE_CALL_ID = True


class WindowsServer2022Profile(EvasionProfile):
    """Windows Server 2022 behavior profile"""

    PROFILE_NAME = "WINDOWS_SERVER_2022"

    # ========================================================================
    # NTLM Configuration - Windows Server 2022
    # ========================================================================

    NTLM_PRODUCT_MAJOR_VERSION = 10
    NTLM_PRODUCT_MINOR_VERSION = 0
    NTLM_PRODUCT_BUILD = 20348  # Windows Server 2022
    NTLM_REVISION = 0x0F

    NTLM_INCLUDE_WORKSTATION = True
    NTLM_WORKSTATION_PREFIX = "WIN-"

    NTLM_USE_SECURE_RANDOM = True

    # ========================================================================
    # Kerberos Configuration - Windows Server 2022
    # ========================================================================

    KRB_AS_REQ_FLAGS = ['forwardable', 'renewable']
    KRB_TGS_REQ_FLAGS = ['forwardable', 'renewable', 'canonicalize']
    KRB_TGS_ETYPE_ORDER = ['aes256_cts_hmac_sha1_96', 'aes128_cts_hmac_sha1_96', 'rc4_hmac']
    KRB_NONCE_BITS = 32
    KRB_TICKET_VALIDITY_HOURS = 10
    KRB_GSS_FLAGS = 0x201E

    # ========================================================================
    # SMB Configuration - Windows Server 2022
    # ========================================================================

    SMB_USE_PROPER_GUID = True
    SMB_CAPABILITIES = 0x7F
    SMB_INCLUDE_311 = True
    SMB_SECURITY_MODE = 0x03  # Servers typically require signing
    SMB_CREDIT_REQUEST = 64
    SMB_CREDIT_THRESHOLD = 1
    SMB_USE_SECURE_RANDOM = True

    # ========================================================================
    # DCE/RPC Configuration - Windows Server 2022
    # ========================================================================

    RPC_MAX_FRAGMENT_SIZE = 5840
    RPC_AUTH_CTX_ID_OFFSET = None
    RPC_SEC_TRAILER_AUTH_CTX_ID = None
    RPC_RANDOMIZE_CALL_ID = True


# ============================================================================
# PROFILE REGISTRY AND HELPERS
# ============================================================================

PROFILES = {
    'DEFAULT': EvasionProfile,
    'WINDOWS_11': Windows11Profile,
    'WINDOWS_10': Windows10Profile,
    'WINDOWS_SERVER_2022': WindowsServer2022Profile,
}

# Global active profile - can be changed at runtime
_active_profile = None

def get_profile():
    """Get the currently active evasion profile"""
    global _active_profile
    if _active_profile is None:
        # Check environment variable for profile selection
        profile_name = os.environ.get('IMPACKET_EVASION_PROFILE', 'DEFAULT')
        _active_profile = PROFILES.get(profile_name.upper(), EvasionProfile)()
    return _active_profile

def set_profile(profile_name):
    """Set the active evasion profile by name"""
    global _active_profile
    profile_name = profile_name.upper()
    if profile_name not in PROFILES:
        raise ValueError(f"Unknown profile: {profile_name}. Available: {list(PROFILES.keys())}")
    _active_profile = PROFILES[profile_name]()
    return _active_profile

def set_profile_instance(profile_instance):
    """Set a custom profile instance"""
    global _active_profile
    _active_profile = profile_instance

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_secure_random_bytes(length):
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(length)

def generate_secure_random_int(bits):
    """Generate cryptographically secure random integer with specified bits"""
    return secrets.randbits(bits)

def generate_proper_guid():
    """Generate a proper Windows-style GUID"""
    return str(uuid_module.uuid4())

def generate_guid_bytes():
    """Generate GUID as 16 bytes"""
    return uuid_module.uuid4().bytes

def generate_workstation_name(prefix="DESKTOP-"):
    """Generate a random Windows-style workstation name"""
    suffix = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(7))
    return f"{prefix}{suffix}"

def get_ntlm_version_bytes(profile=None):
    """Get NTLM VERSION structure bytes for the current profile"""
    if profile is None:
        profile = get_profile()

    return struct.pack('<BBHBBB',
        profile.NTLM_PRODUCT_MAJOR_VERSION,
        profile.NTLM_PRODUCT_MINOR_VERSION,
        profile.NTLM_PRODUCT_BUILD,
        0, 0, 0,  # Reserved 3 bytes
    ) + struct.pack('B', profile.NTLM_REVISION)

def get_kerberos_validity_delta(profile=None):
    """Get ticket validity timedelta for the current profile"""
    if profile is None:
        profile = get_profile()
    return timedelta(hours=profile.KRB_TICKET_VALIDITY_HOURS)

def get_kerberos_nonce(profile=None):
    """Get a Kerberos nonce with appropriate bit size"""
    if profile is None:
        profile = get_profile()
    return secrets.randbits(profile.KRB_NONCE_BITS)

def get_rpc_call_id(current_id=1, profile=None):
    """Get RPC call ID - either sequential or randomized based on profile"""
    if profile is None:
        profile = get_profile()

    if profile.RPC_RANDOMIZE_CALL_ID:
        return secrets.randbelow(0xFFFFFFFF) + 1
    return current_id

def get_rpc_auth_ctx_id(ctx, profile=None):
    """Get RPC auth context ID"""
    if profile is None:
        profile = get_profile()

    if profile.RPC_AUTH_CTX_ID_OFFSET is None:
        return ctx + secrets.randbelow(0x10000)
    return ctx + profile.RPC_AUTH_CTX_ID_OFFSET

def get_rpc_sec_trailer_auth_ctx_id(profile=None):
    """Get SEC_TRAILER default auth_ctx_id"""
    if profile is None:
        profile = get_profile()

    if profile.RPC_SEC_TRAILER_AUTH_CTX_ID is None:
        return secrets.randbelow(0xFFFFFF) + 1
    return profile.RPC_SEC_TRAILER_AUTH_CTX_ID

def get_rpc_max_fragment_size(profile=None):
    """Get RPC maximum fragment size"""
    if profile is None:
        profile = get_profile()
    return profile.RPC_MAX_FRAGMENT_SIZE

def get_rpc_initial_call_id(profile=None):
    """Get initial RPC call ID"""
    if profile is None:
        profile = get_profile()

    if profile.RPC_RANDOMIZE_CALL_ID:
        return secrets.randbelow(0xFFFFFFFE) + 1
    return 1

def get_smb_client_guid(profile=None):
    """Get SMB ClientGuid based on profile"""
    if profile is None:
        profile = get_profile()

    if profile.SMB_USE_PROPER_GUID:
        return generate_guid_bytes()
    else:
        # Original Impacket behavior - ASCII letters only
        import random
        import string
        return ''.join([random.choice(string.ascii_letters) for i in range(16)])

def get_ntlm_challenge(profile=None):
    """Get NTLM client challenge"""
    if profile is None:
        profile = get_profile()

    if profile.NTLM_USE_SECURE_RANDOM:
        return generate_secure_random_bytes(8)
    else:
        # Original Impacket behavior - alphanumeric
        import random
        import string
        from six import b
        return b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(8)]))

def get_smb_nonce(length=11, profile=None):
    """Get SMB encryption nonce"""
    if profile is None:
        profile = get_profile()

    if profile.SMB_USE_SECURE_RANDOM:
        return generate_secure_random_bytes(length)
    else:
        # Original Impacket behavior - ASCII letters
        import random
        import string
        return ''.join([random.choice(string.ascii_letters) for _ in range(length)])

# ============================================================================
# PROFILE INFORMATION
# ============================================================================

def print_profile_info(profile=None):
    """Print current profile configuration"""
    if profile is None:
        profile = get_profile()

    print(f"\n{'='*60}")
    print(f"Impacket Evasion Profile: {profile.PROFILE_NAME}")
    print(f"{'='*60}")

    print(f"\n[NTLM Configuration]")
    print(f"  OS Version: {profile.NTLM_PRODUCT_MAJOR_VERSION}.{profile.NTLM_PRODUCT_MINOR_VERSION} (Build {profile.NTLM_PRODUCT_BUILD})")
    print(f"  NTLM Revision: 0x{profile.NTLM_REVISION:02X}")
    print(f"  Include Workstation: {profile.NTLM_INCLUDE_WORKSTATION}")
    print(f"  Secure Random: {profile.NTLM_USE_SECURE_RANDOM}")

    print(f"\n[Kerberos Configuration]")
    print(f"  AS-REQ Flags: {profile.KRB_AS_REQ_FLAGS}")
    print(f"  TGS-REQ Flags: {profile.KRB_TGS_REQ_FLAGS}")
    print(f"  EType Order: {profile.KRB_TGS_ETYPE_ORDER}")
    print(f"  Nonce Bits: {profile.KRB_NONCE_BITS}")
    print(f"  Ticket Validity: {profile.KRB_TICKET_VALIDITY_HOURS} hours")

    print(f"\n[SMB Configuration]")
    print(f"  Proper GUID: {profile.SMB_USE_PROPER_GUID}")
    print(f"  Capabilities: 0x{profile.SMB_CAPABILITIES:02X}")
    print(f"  Include SMB 3.1.1: {profile.SMB_INCLUDE_311}")
    print(f"  Security Mode: 0x{profile.SMB_SECURITY_MODE:02X}")
    print(f"  Secure Random: {profile.SMB_USE_SECURE_RANDOM}")

    print(f"\n[DCE/RPC Configuration]")
    print(f"  Max Fragment: {profile.RPC_MAX_FRAGMENT_SIZE}")
    print(f"  Randomize Call ID: {profile.RPC_RANDOMIZE_CALL_ID}")
    print(f"{'='*60}\n")
