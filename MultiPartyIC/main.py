# main.py
import os
from functools import reduce 
from myst_simulation.host import Host
from myst_simulation.ic import MystProcessingIC
from myst_simulation.protocols import (
    run_pqc_dkpg_simulation,
    run_pqc_distribute_secret,
    run_pqc_decryption 
)

class SimulationController:
    def __init__(self):
        self.doc_original = "document.txt"
        print("="*60)
        print("=      Myst Architecture: PQC Security Simulation     =")
        print("="*60)
        self._setup_files()

    def _setup_files(self):
        # 1. Create a dummy 10MB file (simulate a sensitive document)
        print(f"\n[Setup] Creating dummy file: {self.doc_original} (10 MB)...")
        content = os.urandom(10 * 1024 * 1024) 
        with open(self.doc_original, 'wb') as f:
            f.write(content)

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    # --- SCENARIO 6: PQC Encryption (Host-to-Quorum) ---
    def run_scenario_6_pqc_encryption(self):
        print("\n\n******************* SCENARIO 6: PQC HOST-TO-QUORUM ENCRYPTION (Kyber) *******************")
        
        # 1. Initialize Actors
        pqc_host = Host(host_id="PQC_HOST")
        pqc_quorum = [MystProcessingIC(f"IC_{i+1}") for i in range(5)]
        
        # 2. Run DKPG (Everyone generates Kyber Keys)
        all_pqc_keys = run_pqc_dkpg_simulation(pqc_quorum)
        pqc_host.set_quorum_pqc_public_keys(all_pqc_keys)
        
        # 3. Host Generates the Master AES File Key (32 bytes)
        K_aes_original = os.urandom(32)
        print(f"\n[Main] Host generated AES key: {K_aes_original.hex()[:20]}...")
        
        # 4. Host Encrypts/Splits/Distributes the Key
        pqc_host.pqc_encrypt_and_distribute_file_key(K_aes_original, pqc_quorum)
        
        # 5. VERIFICATION: Can we reconstruct it?
        # In a real system, the Host would request shares back. 
        # Here we manually peek into the ICs to verify the math works.
        print("\n[Verification] Checking if shares recombine to the original key...")
        shares = [ic.pqc_secret_share for ic in pqc_quorum]
        
        if None not in shares:
            reconstructed = reduce(self._xor_bytes, shares)
            if K_aes_original == reconstructed:
                print("✅ SUCCESS: AES key successfully distributed and verified.")
            else: 
                print("❌ FAILURE: Key mismatch.")
        else:
            print("❌ FAILURE: Some shares were not stored.")

    # --- SCENARIO 7: PQC RNG (Quorum-to-Host) ---
    def run_scenario_7_pqc_rng(self):
        print("\n\n******************* SCENARIO 7: PQC DISTRIBUTED RNG (Kyber) *******************")
        pqc_host = Host(host_id="PQC_HOST")
        pqc_quorum = [MystProcessingIC(f"IC_{i+1}") for i in range(5)]
        
        # 1. Host generates Key (Already done in __init__)
        host_pk = pqc_host.get_pqc_public_key()
        
        # 2. Run Protocol: ICs send random shares to Host
        ciphertexts = run_pqc_decryption(host_pk, pqc_quorum)
        
        # 3. Host decrypts and aggregates
        final_secret = pqc_host.aggregate_and_decrypt_shares(ciphertexts)
        print(f"✅ SUCCESS: Generated PQC Random Secret: {final_secret.hex()[:20]}...")

    def cleanup(self):
        if os.path.exists(self.doc_original): os.remove(self.doc_original)

if __name__ == "__main__":
    sim = SimulationController()
    sim.run_scenario_6_pqc_encryption()
    sim.run_scenario_7_pqc_rng()
    sim.cleanup()