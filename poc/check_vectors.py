"""
Checks the primitives of this proof of concept against their published test
vectors. The vector files are downloaded once, at pinned commits, into .cache/.
"""

import json
import os
import sys
import urllib.request

import mlkem
import xwing


CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")

ACVP = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/"
XWING = "https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/"

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


if __name__ == "__main__":
    total_failed = 0
    for name, check in [("ML-KEM", check_mlkem), ("X-Wing", check_xwing)]:
        passed, failed = check()
        total_failed += failed
        print(f"{name}: {passed} passed, {failed} failed")
    sys.exit(1 if total_failed else 0)
