from tinyec import registry

# Use the same curve specified in the paper's implementation section (NIST P-256)
# Defining it here allows all other modules to import the same constant.
CURVE = registry.get_curve('secp256r1')