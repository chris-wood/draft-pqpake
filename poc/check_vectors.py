"""
Checks the primitives of this proof of concept against their published test
vectors. The vector files are downloaded once, at pinned commits, into .cache/.
"""

import json
import os
import sys
import urllib.request

import cpace
import mlkem
import xwing


CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")

ACVP = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/"
XWING = "https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/"
CPACE = "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-cpace/8fb4056e1b9201927d9f651b9970d9d5660c7892/"

# The scalar and the results of G_X25519.scalar_mult_vfy for the low-order points
# in testvectors.json, from the same commit of draft-irtf-cfrg-cpace. The results
# for all other points are the neutral element.
CPACE_X25519_S = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff"
CPACE_X25519_Q = {
    "Invalid Y6": "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
    "Invalid Y8": "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
    "Invalid Y9": "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
    "Invalid Y10": "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
    "Invalid Y11": "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
}

MLKEM_PARAMS = {
    "ML-KEM-512": mlkem.params512,
    "ML-KEM-768": mlkem.params768,
    "ML-KEM-1024": mlkem.params1024,
}


def load(name, url):
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        os.makedirs(CACHE, exist_ok=True)
        with urllib.request.urlopen(url) as response:
            data = response.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path) as f:
        return json.load(f)


def check_mlkem():
    passed = failed = 0
    h = bytes.fromhex

    keygen = load("acvp-mlkem-keygen.json", ACVP + "ML-KEM-keyGen-FIPS203/internalProjection.json")
    for group in keygen["testGroups"]:
        params = MLKEM_PARAMS[group["parameterSet"]]
        for test in group["tests"]:
            ek, dk = mlkem.KeyGen(h(test["d"]) + h(test["z"]), params)
            if (ek, dk) == (h(test["ek"]), h(test["dk"])):
                passed += 1
            else:
                failed += 1
                print("ML-KEM keyGen failed:", group["parameterSet"], test["tcId"])

    encdec = load("acvp-mlkem-encapdecap.json", ACVP + "ML-KEM-encapDecap-FIPS203/internalProjection.json")
    for group in encdec["testGroups"]:
        params = MLKEM_PARAMS[group["parameterSet"]]
        for test in group["tests"]:
            if group["function"] == "encapsulation":
                c, k = mlkem.Enc(h(test["ek"]), h(test["m"]), params)
                ok = (c, k) == (h(test["c"]), h(test["k"])) and mlkem.Dec(h(test["dk"]), c, params) == k
            elif group["function"] == "decapsulation":
                ok = mlkem.Dec(h(test["dk"]), h(test["c"]), params) == h(test["k"])
            else:
                # The key check functions test input validation that this PoC does not implement.
                continue
            if ok:
                passed += 1
            else:
                failed += 1
                print("ML-KEM", group["function"], "failed:", group["parameterSet"], test["tcId"])

    return passed, failed


def check_xwing():
    passed = failed = 0
    h = bytes.fromhex

    for test in load("xwing.json", XWING + "test-vectors.json"):
        sk, pk = xwing.GenerateKeyPairDerand(h(test["seed"]))
        ss, ct = xwing.EncapsulateDerand(pk, h(test["eseed"]))
        if (sk, pk, ct, ss) == (h(test["sk"]), h(test["pk"]), h(test["ct"]), h(test["ss"])) and xwing.Decapsulate(ct, sk) == ss:
            passed += 1
        else:
            failed += 1
            print("X-Wing failed:", test["seed"])

    return passed, failed


def check_cpace():
    passed = failed = 0
    h = bytes.fromhex
    vectors = load("cpace.json", CPACE + "testvectors.json")
    G, H = cpace.G_X25519(), cpace.H_SHA512()

    v = {name: h(value) for name, value in vectors["G_25519"].items()}
    g = G.calculate_generator(H, v["PRS"], v["CI"], v["sid"])
    Ya = G.scalar_mult(v["ya"], g)
    Yb = G.scalar_mult(v["yb"], g)
    K = G.scalar_mult_vfy(v["ya"], Yb)
    ISK = H.hash(cpace.lv_cat(G.DSI + b"_ISK", v["sid"], K) + cpace.transcript_ir(Ya, v["ADa"], Yb, v["ADb"]))
    for name, value in [("g", g), ("Ya", Ya), ("Yb", Yb), ("K", K), ("K", G.scalar_mult_vfy(v["yb"], Ya)), ("ISK_IR", ISK)]:
        if value == v[name]:
            passed += 1
        else:
            failed += 1
            print("CPace X25519 failed:", name)

    for name, point in vectors["X25519_points"].items():
        expected = h(CPACE_X25519_Q[name]) if name in CPACE_X25519_Q else G.I
        if G.scalar_mult_vfy(h(CPACE_X25519_S), h(point)) == expected:
            passed += 1
        else:
            failed += 1
            print("CPace X25519 scalar_mult_vfy failed:", name)

    return passed, failed


if __name__ == "__main__":
    total_failed = 0
    for name, check in [("ML-KEM", check_mlkem), ("X-Wing", check_xwing), ("CPace", check_cpace)]:
        passed, failed = check()
        total_failed += failed
        print(f"{name}: {passed} passed, {failed} failed")
    sys.exit(1 if total_failed else 0)
