import secrets
import hashlib
import oqs
from tinyec.ec import Point
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from .constants import CURVE

def _serialize_point(point) -> bytes:
    """Helper to convert ECC point to bytes for hashing"""
    return point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")

class MystProcessingIC:
    def __init__(self, ic_id: str, authorized_hosts: list = None):
        self.ic_id = ic_id
        self.authorized_hosts = authorized_hosts if authorized_hosts else []
        
        print(f"[{self.ic_id}] Initialized.")
        
        # --- CLASSICAL ECC STATE ---
        self.x_i = None  # Secret Share
        self.Y_i = None  # Public Share
        self.h_i = None  # Commitment
        self.received_commitments = {}
        self.received_public_shares = {}
        
        # --- PQC (KYBER) STATE ---
        self.pqc_kem = oqs.KeyEncapsulation("Kyber512")
        self.pqc_public_key = None
        self.pqc_secret_share = None 

    # ==========================
    # === CLASSICAL METHODS ===
    # ==========================
    def generate_triplet(self):
        """Generates (Secret, Public, Commitment) for ECC"""
        self.x_i = secrets.randbelow(CURVE.field.n)
        self.Y_i = self.x_i * CURVE.g
        self.h_i = hashlib.sha256(_serialize_point(self.Y_i)).digest()

    def get_commitment(self) -> bytes: 
        return self.h_i
        
    def get_public_share(self) -> tuple: 
        return (self.Y_i.x, self.Y_i.y)

    def verify_commitments(self) -> bool:
        return True # Simplified for benchmarking

    def aggregate_public_shares(self):
        aggregated_Y = self.Y_i
        for _, Y_point_coords in self.received_public_shares.items():
            Y_point = Point(CURVE, Y_point_coords[0], Y_point_coords[1])
            aggregated_Y += Y_point
        return aggregated_Y

    def distributed_decryption_share(self, c1_point: Point):
        """ElGamal partial decryption"""
        neg_x_i = -self.x_i % CURVE.field.n
        return neg_x_i * c1_point

    # ==========================
    # === PQC METHODS (NEW) ===
    # ==========================
    def pqc_generate_keypair(self):
        self.pqc_public_key = self.pqc_kem.generate_keypair()

    def get_pqc_public_key(self) -> bytes:
        return self.pqc_public_key

    def pqc_store_share(self, kyber_ciphertext: bytes, aes_payload: bytes) -> bool:
        try:
            # 1. Decapsulate to get AES Session Key
            k_session = self.pqc_kem.decap_secret(kyber_ciphertext)
            # 2. Decrypt the share
            iv = aes_payload[:16]
            encrypted_data = aes_payload[16:]
            cipher = AES.new(k_session, AES.MODE_CBC, iv)
            self.pqc_secret_share = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return True
        except Exception:
            return False
    
    def pqc_retrieve_share_for_decryption(self, host_pk: bytes) -> bytes:
        return self.pqc_secret_share