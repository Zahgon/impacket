# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import math
import struct
from impacket.dcerpc.v5.gkdi import ECDHKey, FFCDHKey, GroupKeyEnvelope
from impacket.ldap.ldaptypes import ACE, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, SR_SECURITY_DESCRIPTOR, LDAP_SID
from impacket.structure import Structure
from Cryptodome.Hash import SHA512, SHA256, HMAC
from Cryptodome.Util.number import long_to_bytes
from Cryptodome.Util.py3compat import iter_range
from Cryptodome.Cipher import AES

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")
KEK_PUBLIC_KEY_LABEL = "KDS public key\0".encode("utf-16le")

def SP800_108_Counter(master, key_len, prf, num_keys=None, label=b'', context=b''):
    """Derive one or more keys from a master secret using
    a pseudorandom function in Counter Mode, as specified in
    `NIST SP 800-108r1 <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf>`_.

    Modified version for Impacket, accepting null_bytes

    Args:
     master (byte string):
        The secret value used by the KDF to derive the other keys.
        It must not be a password.
        The length on the secret must be consistent with the input expected by
        the :data:`prf` function.
     key_len (integer):
        The length in bytes of each derived key.
     prf (function):
        A pseudorandom function that takes two byte strings as parameters:
        the secret and an input. It returns another byte string.
     num_keys (integer):
        The number of keys to derive. Every key is :data:`key_len` bytes long.
        By default, only 1 key is derived.
     label (byte string):
        Optional description of the purpose of the derived keys.
        It must not contain zero bytes.
     context (byte string):
        Optional information pertaining to
        the protocol that uses the keys, such as the identity of the
        participants, nonces, session IDs, etc.
        It must not contain zero bytes.

    Return:
        - a byte string (if ``num_keys`` is not specified), or
        - a tuple of byte strings (if ``num_key`` is specified).
    """
    pass

class KeyIdentifier(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Magic', '<L=0'),
        ('Flags', '<L=0'),
        ('L0Index', '<L=0'),
        ('L1Index', '<L=0'),
        ('L2Index', '<L=0'),
        ('RootKeyId', '16s=b'),
        ('UnknownLength', '<L=0'),
        ('DomainLength', '<L=0'),
        ('ForestLength', '<L=0'),
        ('_Unknown','_-Unknown', 'self["UnknownLength"]'),
        ('Unknown',':'),
        ('_Domain','_-Domain', 'self["DomainLength"]'),
        ('Domain',':'),
        ('_Forest','_-Forest', 'self["ForestLength"]'),
        ('Forest',':'),
    )

    def dump(self):
        print("[KEY IDENTIFIER]")
        print("Version:\t\t%s" % (self['Version']))
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("Flags:\t\t%s" % (self['Flags']))
        print("L0Index:\t\t%s" % (self['L0Index']))
        print("L1Index:\t\t%s" % (self['L1Index']))
        print("L2Index:\t\t%s" % (self['L2Index']))
        print("RootKeyId:\t\t%s" % (self['RootKeyId']))
        print("Unknown:\t\t%s" % (self['Unknown']))
        print("Domain:\t\t%s" % (self['Domain'].decode('utf-16le')))
        print("Forest:\t\t%s" % (self['Forest'].decode('utf-16le')))
        print()
    
    def is_public_key(self) -> bool:
        pass
    
class EncryptedPasswordBlob(Structure):
    structure = (
        ('Timestamp_lower', '<L=0'),
        ('Timestamp_upper', '<L=0'),
        ('Length', '<L=0'),
        ('Flags', '<L=0'),
        ('_Blob','_-Blob', 'self["Length"]'),
        ('Blob',':')
    )

    def dump(self):
        print("[ENCRYPTED PASSWORD BLOB]")
        print("Timestamp_upper:\t\t%s" % (self['Timestamp_upper']))
        print("Timestamp_lower:\t\t%s" % (self['Timestamp_lower']))
        print("Update Timestamp:\t\t%s" % ((int(self['Timestamp_upper']) << 32) | self['Timestamp_lower']))
        print("Length:\t\t%s" % (self['Length']))
        print("Flags:\t\t%s" % (self['Flags']))
        print("Blob:\t\t%s" % (self['Blob']))
        print()

def int_to_u32be(n: int) -> bytes:
    pass

def create_ace(sid, mask):
    pass

def create_sd(sid):
    pass

def compute_kdf_hash(length, key_material, otherinfo):
    pass

def compute_kdf_context(key_guid, l0, l1, l2):
    pass

def kdf(hash_alg_str, secret, label, context, length):
    pass

def compute_l2_key(key_id: KeyIdentifier, gke: GroupKeyEnvelope):
    pass

def generate_kek_secret_from_pubkey(gke: GroupKeyEnvelope, key_id: KeyIdentifier,l2_key: bytes):
    pass
    
def compute_kek(gke: GroupKeyEnvelope, key_id: KeyIdentifier):
    pass

def aes_unwrap(wrapping_key: bytes, wrapped_key: bytes):
    pass

def unwrap_cek(kek, encrypted_cek):
    pass

def decrypt_plaintext(cek, iv, encrypted_blob):
    pass
