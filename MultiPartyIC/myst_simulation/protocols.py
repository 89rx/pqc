import os
import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- CLASSICAL PROTOCOLS ---
def run_ecc_dkpg(quorum):
    # Phase 1: Gen
    for ic in quorum: ic.generate_triplet()
    # Phase 2: Commitment Exchange (Quadratic complexity simulation)
    commits = {ic.ic_id: ic.get_commitment() for ic in quorum}
    for ic in quorum: ic.received_commitments = commits
    # Phase 3: Public Share Exchange (Quadratic complexity simulation)
    pub_shares = {ic.ic_id: ic.get_public_share() for ic in quorum}
    for ic in quorum: ic.received_public_shares = pub_shares
    # Phase 4: Aggregate
    agg_key = quorum[0].aggregate_public_shares()
    return agg_key

def run_ecc_decryption_request(host, c1, quorum):
    return [ic.distributed_decryption_share(c1) for ic in quorum]

# --- PQC PROTOCOLS ---
def run_pqc_dkpg(quorum):
    keys = {}
    for ic in quorum:
        ic.pqc_generate_keypair()
        keys[ic.ic_id] = ic.get_pqc_public_key()
    return keys

def run_pqc_distribute_secret(host, shares, quorum):
    for i, ic in enumerate(quorum):
        share = shares[i]
        pk = host.quorum_pqc_public_keys[ic.ic_id]
        
        # Kyber Encap
        kem = oqs.KeyEncapsulation("Kyber512")
        ct, k_sess = kem.encap_secret(pk)
        
        # AES Encrypt
        iv = os.urandom(16)
        cipher = AES.new(k_sess, AES.MODE_CBC, iv)
        payload = iv + cipher.encrypt(pad(share, AES.block_size))
        
        # Send
        ic.pqc_store_share(ct, payload)
    return True