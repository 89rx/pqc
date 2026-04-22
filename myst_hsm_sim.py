import os
import ctypes
import oqs
import numpy as np
import galois
import time
import sys

# Initialize GF(2^8) for byte-wise Shamir's Secret Sharing
GF = galois.GF(2**8)
KEM_ALG = "Kyber512"
TOTAL_N = 50
THRESHOLD_T = int(0.6 * TOTAL_N)


# --- Timing Display Helpers ---
def _ns_to_ms(ns):
    return ns / 1e6

def _print_timing_row(label, elapsed_ns, width=45):
    ms = _ns_to_ms(elapsed_ns)
    us = elapsed_ns / 1e3
    if ms >= 1.0:
        val = f"{ms:.3f} ms"
    else:
        val = f"{us:.1f} us"
    print(f"  {'|'} {label:<{width}} {val:>12} {'|'}")

def _print_divider(width=60):
    print("  +" + "-" * width + "+")

# --- Protocol Classes ---
class ProcessingIC:
    """Simulates an untrusted IC holding a single GF(256) share."""
    def __init__(self, ic_id, share_data):
        self.ic_id = ic_id
        self.share_data = share_data

    def request_share(self):
        return (self.ic_id, self.share_data)

class MystHost:
    """Phase 1: Trusted Dealer. Generates the key and distributes GF(256) shares."""
    def __init__(self):
        t0 = time.perf_counter_ns()
        self.kem = oqs.KeyEncapsulation(KEM_ALG)
        self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.secret_key
        self.sk_bytes = np.frombuffer(self.secret_key, dtype=np.uint8)
        self.t_keygen = time.perf_counter_ns() - t0
        
    def distribute_shares(self):
        t0_setup = time.perf_counter_ns()
        sk_len = len(self.sk_bytes)
        # Convert SK to GF(256) array
        sk_gf = GF(self.sk_bytes)
        
        # Generate random polynomial coefficients (t-1 degree) for each byte
        # Shape: (t-1, 1632)
        random_coeffs = GF.Random((THRESHOLD_T - 1, sk_len))
        t_gf_setup = time.perf_counter_ns() - t0_setup
        
        t0_eval = time.perf_counter_ns()
        ics = []
        for i in range(1, TOTAL_N + 1):
            x_val = GF(i)
            
            # FIX: Use native .copy() to preserve the GF(256) typing
            share_val = sk_gf.copy() 
            
            x_power = GF(1)
            for degree in range(THRESHOLD_T - 1):
                x_power = x_power * x_val
                share_val += random_coeffs[degree] * x_power
            
            ics.append(ProcessingIC(i, share_val))
        t_poly_eval = time.perf_counter_ns() - t0_eval
            
        # The Host securely deletes the master key from memory here
        self.kem.free()
        
        timings = {
            "t_keygen": self.t_keygen,
            "t_gf_setup": t_gf_setup,
            "t_poly_eval": t_poly_eval
        }
        return self.public_key, ics, timings

class MystController:
    """Phase 3: Reconstructs the key via Lagrange interpolation and decapsulates."""
    def __init__(self):
        pass

    def reconstruct_and_decap(self, shares, ciphertext):
        # 1. PAPER REQUIREMENT: Enforce Distinct IC IDs to prevent Clone-Share Attack
        unique_ids = set([s[0] for s in shares])
        if len(unique_ids) < THRESHOLD_T:
            raise ValueError("CRITICAL: Threshold not met or duplicate shares detected!")
        
        print(f"[*] Controller securely collected distinct shares from ICs: {unique_ids}")
        
        # 2. GF(256) Lagrange Interpolation at x = 0
        t0_lagrange = time.perf_counter_ns()
        x_coords = GF([s[0] for s in shares])
        y_coords = [s[1] for s in shares]
        
        reconstructed_sk_gf = GF.Zeros(len(y_coords[0]))
        
        for i in range(THRESHOLD_T):
            # Calculate Lagrange basis polynomial L_i(0)
            basis = GF(1)
            for j in range(THRESHOLD_T):
                if i != j:
                    numerator = x_coords[j]
                    denominator = x_coords[j] - x_coords[i]
                    basis *= (numerator / denominator)
            reconstructed_sk_gf += y_coords[i] * basis
            
        reconstructed_bytes = bytes(np.array(reconstructed_sk_gf, dtype=np.uint8))
        t_lagrange = time.perf_counter_ns() - t0_lagrange
        
        # 3. The ctypes Memory Bridge into liboqs
        t0_decap = time.perf_counter_ns()
        with oqs.KeyEncapsulation(KEM_ALG) as kem_receiver:
            sk_len = kem_receiver.details['length_secret_key']
            
            if len(reconstructed_bytes) != sk_len:
                raise ValueError(f"Reconstructed key length mismatch! Expected {sk_len}, got {len(reconstructed_bytes)}")
                
            c_type_buffer = (ctypes.c_ubyte * sk_len).from_buffer_copy(reconstructed_bytes)
            kem_receiver.secret_key = c_type_buffer  
            
            rcvd_secret = kem_receiver.decap_secret(ciphertext)
        t_decap = time.perf_counter_ns() - t0_decap
        
        timings = {
            "t_lagrange": t_lagrange,
            "t_decap": t_decap
        }
        return rcvd_secret, timings

# --- EXECUTION FLOW ---
def run_myst_hsm_protocol():
    print(f"=== Myst HSM Protocol: GF(256) SSS + ML-KEM ({THRESHOLD_T}-of-{TOTAL_N}) ===")
    
    t_protocol_start = time.perf_counter_ns()

    # 1. Host Phase
    host = MystHost()
    pubkey, network_ics, phase1_timings = host.distribute_shares()
    print("[+] Phase 1: Host generated Kyber512 keys and distributed GF(256) shares.")
    
    # 2. Sender Phase
    t0_encap = time.perf_counter_ns()
    with oqs.KeyEncapsulation(KEM_ALG) as sender:
        ciphertext, sent_secret = sender.encap_secret(pubkey)
    t_encap = time.perf_counter_ns() - t0_encap
    print(f"[+] Phase 2: Sender encapsulated secret: {sent_secret[:8].hex()}...")
    
# 3. Controller Phase (Touch of Evil Scenario)
    controller = MystController()
    
    t0_collection = time.perf_counter_ns()
    
    # FIX: Dynamically sample exactly THRESHOLD_T distinct ICs from the network
    import random
    active_committee = random.sample(network_ics, THRESHOLD_T)
    collected_shares = [ic.request_share() for ic in active_committee]
    
    t_collection = time.perf_counter_ns() - t0_collection
    
    rcvd_secret, phase3_timings = controller.reconstruct_and_decap(collected_shares, ciphertext)
    
    # 4. Verifier Phase
    t_protocol_total = time.perf_counter_ns() - t_protocol_start

    if sent_secret == rcvd_secret:
        print(f"[SUCCESS] Shared secret successfully decapsulated: {rcvd_secret[:8].hex()}...")
    else:
        print("[FAIL] Decapsulation mismatch.")
        return

    # -------------------------------------------------------------------------
    # TIMING SUMMARY
    # -------------------------------------------------------------------------
    t_phase1_total = phase1_timings['t_keygen'] + phase1_timings['t_gf_setup'] + phase1_timings['t_poly_eval']
    t_phase3_total = t_collection + phase3_timings['t_lagrange'] + phase3_timings['t_decap']

    print(f"\n{'='*64}")
    print(f"  TIMING SUMMARY  ({THRESHOLD_T}-of-{TOTAL_N} GF(256) SSS + Kyber512 HSM)")
    print(f"{'='*64}")

    print(f"\n  -- Phase 1: Key Generation & Distribution (Trusted Host) --")
    _print_divider()
    _print_timing_row("ML-KEM Keypair Generation", phase1_timings['t_keygen'])
    _print_timing_row("GF(256) Array Setup & Random Coeffs", phase1_timings['t_gf_setup'])
    _print_timing_row(f"Polynomial Evaluation x{TOTAL_N} (all nodes)", phase1_timings['t_poly_eval'])
    _print_divider()
    _print_timing_row("Phase 1 Subtotal", t_phase1_total)
    _print_divider()

    print(f"\n  -- Phase 2: Encapsulation (Sender) --")
    _print_divider()
    _print_timing_row("ML-KEM Encapsulation", t_encap)
    _print_divider()

    print(f"\n  -- Phase 3: Reconstruction & Decapsulation (Controller) --")
    _print_divider()
    _print_timing_row(f"Share Collection ({THRESHOLD_T} distinct nodes)", t_collection)
    _print_timing_row("GF(256) Lagrange Interpolation", phase3_timings['t_lagrange'])
    _print_timing_row("ctypes Memory Bridge + ML-KEM Decap", phase3_timings['t_decap'])
    _print_divider()
    _print_timing_row("Phase 3 Subtotal", t_phase3_total)
    _print_divider()

    print(f"\n  -- Overall --")
    _print_divider()
    _print_timing_row("TOTAL PROTOCOL WALL TIME", t_protocol_total)
    _print_divider()
    print()

if __name__ == "__main__":
    run_myst_hsm_protocol()