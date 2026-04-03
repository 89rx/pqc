import oqs

print("Enabled Signature Mechanisms:")
sigs = oqs.get_enabled_sig_mechanisms()
for s in sigs:
    print(f" - {s}")

if "Dilithium2" in sigs:
    print("\n✅ You should use: 'Dilithium2'")
elif "ML-DSA-44" in sigs:
    print("\n✅ You should use: 'ML-DSA-44' (The new NIST standard name for Dilithium2)")
else:
    print("\n❌ Dilithium not found! You might need to reinstall liboqs.")