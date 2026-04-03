import os
import secrets
import oqs
from functools import reduce
from tinyec.ec import Point
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from .constants import CURVE
from .protocols import run_pqc_distribute_secret

class Host:
    def __init__(self, host_id: str, aggregated_public_key: Point = None):
        self.host_id = host_id
        # ECC State
        self.Y_agg = aggregated_public_key
        # PQC State
        self.quorum_pqc_public_keys = {}
        self.pqc_kem = oqs.KeyEncapsulation("Kyber512")
        self.pqc_public_key = self.pqc_kem.generate_keypair()

    # ==========================
    # === CLASSICAL METHODS ===
    # ==========================
    def _map_msg(self, msg: bytes) -> Point:
        # Simplified mapping for benchmark speed
        return CURVE.g * 123 

    def encrypt_ecc(self, message: bytes) -> tuple:
        """ Standard ElGamal Encryption """
        M_point = self._map_msg(message)
        r = secrets.randbelow(CURVE.field.n)
        c1 = r * CURVE.g
        c2 = M_point + (r * self.Y_agg)
        return (c1, c2)

    def decrypt_ecc(self, c2_point: Point, shares: list) -> bool:
        """ Aggregate shares and subtract from c2 """
        aggregated_D = shares[0]
        for s in shares[1:]: aggregated_D += s
        M_recovered = c2_point + aggregated_D
        return True

    # ==========================
    # === PQC METHODS (NEW) ===
    # ==========================
    def set_quorum_pqc_keys(self, keys: dict):
        self.quorum_pqc_public_keys = keys

    def _xor(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt_pqc(self, file_key: bytes, quorum: list) -> bool:
        """ 1. Split AES key, 2. Encrypt & Distribute via Kyber """
        shares = []
        temp = file_key
        for _ in range(len(quorum) - 1):
            s = os.urandom(32)
            shares.append(s)
            temp = self._xor(temp, s)
        shares.append(temp)
        
        return run_pqc_distribute_secret(self, shares, quorum)

    def decrypt_pqc(self, shares: list) -> bytes:
        """ Reconstruct via XOR """
        return reduce(self._xor, shares)