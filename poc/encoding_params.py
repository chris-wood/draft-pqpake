import math


q = 3329
log2_q = math.log2(q)

t = 256
N_max = 5  # In ML-KEM1024, we need N=5 encodings to represent an entire ciphertext
N_max_log2 = math.log2(N_max)

# The dominating term is in ciphertext uniformity
# We need: N_max * eps * 2^(1 - bitlength) <= 2^-sec

sec = 230  # ML-KEM1024 is estimated to provide 230 bits of IND-CCA2 security
m_limit_bits = 256

    
pow_qt = q**t
pow_qt_bits = math.ceil(math.log2(pow_qt))
for z in range(pow_qt_bits, pow_qt_bits + m_limit_bits):
    # Compute what m has to be
    pow2_of_z = 1 << z
    m_plus_1 = pow2_of_z // pow_qt  # Floor rounding, we do not like the number to go above (although that probability is negligible)
    
    # Compute the final upper bound of the encoding
    upper_bound = m_plus_1 * pow_qt

    eps = pow2_of_z - upper_bound

    # Enforce the constraint
    if (N_max_log2 + math.log2(eps) + 1 - z) > -sec:
        continue

    # Compute the remaining parameters
    bigint_bits = math.ceil(math.log2(upper_bound))
    bigint_bytes = math.ceil(bigint_bits / 8)
    padding_bits = bigint_bytes * 8 - bigint_bits
    mask = sum(1 << i for i in range(8 - padding_bits, 8))
    m = m_plus_1 - 1
    print(m, bigint_bytes, mask)
    break
else:
    print("No matching parameters")
