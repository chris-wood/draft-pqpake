"""
Generates the test vectors of draft-vos-cfrg-pqpake. It writes one JSON file per
configuration with test vectors, ml-bua-skem.json with the vectors of
ML-BUA-sKEM, and test-vectors.md, which renders all vectors for the Test Vectors
section of the specification. All files are written to vectors/.
"""

import json
import os

import util
from cpaceoquake_plus import (cpaceoquakeplus_init, cpaceoquakeplus_respond, cpaceoquakeplus_initiator_continue,
                              cpaceoquakeplus_responder_continue, cpaceoquakeplus_initiator_finish,
                              cpaceoquakeplus_responder_finish)
from cpaceoquake import cpaceoquake_init, cpaceoquake_respond, cpaceoquake_initiator_finish, cpaceoquake_responder_finish
from deps import AuthenticationError, CPaceError
from drbg import ReplayRNG, UnsafeDRBG
from ml_bua_skem import MLBUASKEM768, MLBUASKEM1024
from oquake import oquake_init, oquake_respond, oquake_finish
from oquake_plus import oquakeplus_init, oquakeplus_respond, oquakeplus_finish, oquakeplus_verify
from params import CONFIGURATIONS
from pwconf import GenVerifier, encode_registration
from util import EncodePublicContext, lv_encode


OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")

PRS = b"password"
U = b"client"
S = b"server"
SECRET_CONTEXT = b""

LINE_LENGTH = 69


class Run:
    """Records the randomness and intermediate values of one run of a protocol."""

    def __init__(self, name, replay=None):
        self.inputs = UnsafeDRBG(b"draft-vos-cfrg-pqpake inputs " + name.encode())
        if replay is None:
            self.rng = UnsafeDRBG(b"draft-vos-cfrg-pqpake randomness " + name.encode())
        else:
            self.rng = ReplayRNG(replay)
        util.TRACE = []

    def randomness(self):
        values = {}
        for label, value in self.rng.draws:
            if label == "kemeleon_m":
                values.setdefault(label, []).append(value)
            else:
                assert label is not None and label not in values, label
                values[label] = value
        return values

    def intermediate(self, labels):
        # Both parties trace some values; they must agree.
        values = {}
        for label, value in util.TRACE:
            if label in labels:
                assert values.get(label, value) == value, label
                values[label] = value
        return {label: values[label] for label in labels}


def ml_bua_skem_vector(kem, replay=None):
    run = Run(kem.name, replay)
    sk, upk = kem.KeyGen(run.rng)
    k, ct = kem.Encaps(upk, run.rng)
    assert kem.Decaps(ct, sk) == k
    return {
        "name": kem.name,
        "randomness": run.randomness(),
        "outputs": {"upk": upk, "ct": ct, "k": k},
    }


def oquake_vector(identifier, replay=None):
    params = CONFIGURATIONS[identifier]
    run = Run(identifier, replay)
    sid = run.inputs.random_bytes(16)
    public_context = EncodePublicContext(sid, U, S)

    state, init_msg = oquake_init(params, PRS, public_context, SECRET_CONTEXT, run.rng)
    resp_msg, key, th = oquake_respond(params, PRS, public_context, SECRET_CONTEXT, init_msg, run.rng)
    assert oquake_finish(params, state, resp_msg, run.rng) == (key, th)

    return {
        "name": "OQUAKE",
        "inputs": {"PRS": PRS, "sid": sid, "U": U, "S": S, "public_context": public_context,
                   "secret_context": SECRET_CONTEXT},
        "randomness": run.randomness(),
        "intermediate": run.intermediate(["oquake_upk", "oquake_k"]),
        "messages": {"init_msg": init_msg, "resp_msg": resp_msg},
        "outputs": {"key": key, "th": th},
    }


def cpaceoquake_vector(identifier, replay=None):
    params = CONFIGURATIONS[identifier]
    run = Run(identifier, replay)
    sid = run.inputs.random_bytes(16)
    public_context = EncodePublicContext(sid, U, S)

    client_state, msg1 = cpaceoquake_init(params, PRS, public_context, SECRET_CONTEXT, run.rng)
    server_state, msg2 = cpaceoquake_respond(params, PRS, public_context, SECRET_CONTEXT, msg1, run.rng)
    key, msg3, th = cpaceoquake_initiator_finish(params, PRS, public_context, SECRET_CONTEXT, client_state, msg2, run.rng)
    assert cpaceoquake_responder_finish(params, server_state, msg3, run.rng) == (key, th)

    return {
        "name": "CPaceOQUAKE",
        "inputs": {"PRS": PRS, "sid": sid, "U": U, "S": S, "public_context": public_context,
                   "secret_context": SECRET_CONTEXT},
        "randomness": run.randomness(),
        "intermediate": run.intermediate(["cpace_ISK", "cpace_th", "oquake_upk", "oquake_k", "oquake_key"]),
        "messages": {"msg1": msg1, "msg2": msg2, "msg3": msg3},
        "outputs": {"key": key, "th": th},
    }


def oquakeplus_vector(identifier, replay=None):
    params = CONFIGURATIONS[identifier]
    run = Run(identifier, replay)
    sid = run.inputs.random_bytes(16)
    salt = run.inputs.random_bytes(32)
    public_context = EncodePublicContext(sid, U, S)

    v, pk, kem_blind = GenVerifier(params.pwconf_params, PRS, salt, U, S, run.rng)
    reg_msg = encode_registration(salt, v, pk, kem_blind, U, S)

    client_state, init_msg = oquakeplus_init(params, PRS, salt, U, S, public_context, SECRET_CONTEXT, run.rng)
    server_state, resp_msg = oquakeplus_respond(params, v, public_context, SECRET_CONTEXT, init_msg, pk, kem_blind, run.rng)
    key, response, th = oquakeplus_finish(params, client_state, resp_msg, run.rng)
    assert oquakeplus_verify(server_state, response) == (key, th)

    return {
        "name": "OQUAKE+",
        "inputs": {"PRS": PRS, "salt": salt, "U": U, "S": S, "sid": sid, "public_context": public_context,
                   "secret_context": SECRET_CONTEXT},
        "randomness": run.randomness(),
        "intermediate": run.intermediate(["v", "seed", "pk", "oquake_upk", "oquake_k", "oquake_key", "oquake_th", "pc_k"]),
        "messages": {"reg_msg": reg_msg, "init_msg": init_msg, "resp_msg": resp_msg, "response": response},
        "outputs": {"key": key, "th": th},
    }


def cpaceoquakeplus_run(identifier, name, client_PRS=PRS, replay=None):
    """Runs CPaceOQUAKE+ with registration, up to the point where it fails, if it does."""
    params = CONFIGURATIONS[identifier]
    run = Run(name, replay)
    sid = run.inputs.random_bytes(16)
    salt = run.inputs.random_bytes(32)
    public_context = EncodePublicContext(sid, U, S)

    inputs = {"PRS": PRS, "salt": salt, "U": U, "S": S, "sid": sid, "public_context": public_context,
              "secret_context": SECRET_CONTEXT}
    if client_PRS != PRS:
        inputs["client_PRS"] = client_PRS

    v, pk, kem_blind = GenVerifier(params.pwconf_params, PRS, salt, U, S, run.rng)
    messages = {"reg_msg": encode_registration(salt, v, pk, kem_blind, U, S)}

    client_state, messages["msg1"] = cpaceoquakeplus_init(params, client_PRS, salt, U, S, public_context, SECRET_CONTEXT, run.rng)
    server_state, messages["msg2"] = cpaceoquakeplus_respond(params, v, public_context, SECRET_CONTEXT, messages["msg1"], run.rng)
    client_state, messages["msg3"] = cpaceoquakeplus_initiator_continue(params, client_state, messages["msg2"], run.rng)
    server_state, messages["msg4"] = cpaceoquakeplus_responder_continue(params, server_state, messages["msg3"], pk, kem_blind, run.rng)
    try:
        key, messages["msg5"], th = cpaceoquakeplus_initiator_finish(params, client_state, messages["msg4"])
    except AuthenticationError:
        return run, inputs, messages, None, server_state
    assert cpaceoquakeplus_responder_finish(server_state, messages["msg5"]) == (key, th)
    return run, inputs, messages, {"key": key, "th": th}, server_state


def cpaceoquakeplus_vectors(identifier):
    run, inputs, messages, outputs, server_state = cpaceoquakeplus_run(identifier, identifier)
    vectors = [{
        "name": "CPaceOQUAKE+",
        "inputs": inputs,
        "randomness": run.randomness(),
        "intermediate": run.intermediate(["v", "seed", "pk", "cpace_ISK", "cpace_th", "oquake_upk", "oquake_k",
                                          "oquake_key", "oquake_th", "cpaceoquake_key", "pc_k"]),
        "messages": messages,
        "outputs": outputs,
    }]

    # The server rejects a server_confirm value that does not match its own.
    wrong_msg5 = bytes([messages["msg5"][0] ^ 1]) + messages["msg5"][1:]
    try:
        cpaceoquakeplus_responder_finish(server_state, wrong_msg5)
        assert False
    except AuthenticationError:
        pass
    vectors.append({
        "name": "CPaceOQUAKE+ with an incorrect server_confirm",
        "summary": "This vector uses the inputs, randomness, and messages msg1 to msg4 of the CPaceOQUAKE+ "
                   "vector. A server that receives the following msg5 raises AuthenticationError.",
        "inputs": inputs,
        "randomness": run.randomness(),
        "messages": dict(messages, msg5=wrong_msg5),
        "error": "AuthenticationError, raised by the server on receipt of msg5",
        "render": {"msg5": wrong_msg5},
    })

    # A client with the wrong password fails password confirmation.
    run, inputs, messages, outputs, _ = cpaceoquakeplus_run(identifier, identifier + " wrong password",
                                                            client_PRS=b"wrong password")
    assert outputs is None
    vectors.append({
        "name": "CPaceOQUAKE+ with the wrong password",
        "inputs": inputs,
        "randomness": run.randomness(),
        "messages": messages,
        "error": "AuthenticationError, raised by the client on receipt of msg4",
    })

    # The server aborts if Ya is the neutral element, whatever its other inputs. This
    # vector repeats the inputs and registration of the first vector.
    params = CONFIGURATIONS[identifier]
    run = Run(identifier)
    sid = run.inputs.random_bytes(16)
    salt = run.inputs.random_bytes(32)
    public_context = EncodePublicContext(sid, U, S)
    v, pk, kem_blind = GenVerifier(params.pwconf_params, PRS, salt, U, S, run.rng)
    reg_msg = encode_registration(salt, v, pk, kem_blind, U, S)
    assert reg_msg == vectors[0]["messages"]["reg_msg"]
    msg1 = lv_encode(params.cpaceoquake_params.cpace_params.G.I)
    try:
        cpaceoquakeplus_respond(params, v, public_context, SECRET_CONTEXT, msg1, run.rng)
        assert False
    except CPaceError:
        pass
    vectors.append({
        "name": "CPaceOQUAKE+ with the neutral element as Ya",
        "summary": "A server that receives the following msg1, in which Ya is the neutral element, raises "
                   "CPaceError, whatever its other inputs. In the JSON file, this vector uses the inputs and "
                   "registration of the CPaceOQUAKE+ vector.",
        "inputs": vectors[0]["inputs"],
        "randomness": run.randomness(),
        "messages": {"reg_msg": reg_msg, "msg1": msg1},
        "error": "CPaceError, raised by the server on receipt of msg1",
        "render": {"msg1": msg1},
    })
    return vectors


def to_json(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [to_json(v) for v in value]
    if isinstance(value, dict):
        return {k: to_json(v) for k, v in value.items() if k != "render"}
    return value


def from_json_randomness(values):
    return {label: [int(v) for v in value] if isinstance(value, list) else bytes.fromhex(value)
            for label, value in values.items()}


def check_replay(path):
    """Checks that each vector in a JSON file can be reproduced from its listed randomness alone."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        for vector, kem in zip(data, [MLBUASKEM768(), MLBUASKEM1024()]):
            replay = from_json_randomness(vector["randomness"])
            replayed = ml_bua_skem_vector(kem, replay)
            assert to_json(replayed) == vector, vector["name"]
        return
    identifier = data["configuration"]
    for vector in data["vectors"]:
        replay = from_json_randomness(vector["randomness"])
        if vector["name"] == "OQUAKE":
            replayed = oquake_vector(identifier, replay)
        elif vector["name"] == "OQUAKE+":
            replayed = oquakeplus_vector(identifier, replay)
        elif vector["name"] == "CPaceOQUAKE":
            replayed = cpaceoquake_vector(identifier, replay)
        elif vector["name"] == "CPaceOQUAKE+":
            run, _, messages, outputs, _ = cpaceoquakeplus_run(identifier, identifier, replay=replay)
            replayed = dict(vector, messages=to_json(messages), outputs=to_json(outputs))
            run.rng.assert_consumed()
        elif vector["name"] == "CPaceOQUAKE+ with the wrong password":
            run, _, messages, outputs, _ = cpaceoquakeplus_run(identifier, identifier + " wrong password",
                                                               client_PRS=b"wrong password", replay=replay)
            assert outputs is None
            replayed = dict(vector, messages=to_json(messages))
            run.rng.assert_consumed()
        else:
            # The remaining vectors differ from the above in one received message.
            continue
        assert to_json(replayed) == vector, vector["name"]


def render_value(name, value):
    # Values that do not fit on the line of their name follow on separate lines,
    # with 32 bytes (or one integer) per line.
    if isinstance(value, list):
        return [name + ":"] + [str(v) for v in value]
    text = value.hex()
    if len(name) + 2 + len(text) <= LINE_LENGTH:
        return [(name + ": " + text).rstrip()]
    return [name + ":"] + [text[i:i + 64] for i in range(0, len(text), 64)]


def render_vector(vector):
    if "render" in vector:
        # A compact rendering of a vector that differs from an earlier one in one message
        lines = []
        for name, value in vector["render"].items():
            lines.extend(render_value(name, value))
        return vector["summary"] + "\n\n~~~\n" + "\n".join(lines) + "\n~~~\n"
    lines = []
    for group, title in [("inputs", "Inputs"), ("randomness", "Randomness"), ("intermediate", "Intermediate values"),
                         ("messages", "Messages"), ("outputs", "Outputs")]:
        if group in vector:
            if lines:
                lines.append("")
            lines.append("# " + title)
            for name, value in vector[group].items():
                lines.extend(render_value(name, value))
    if "error" in vector:
        lines.extend(["", "# Error", vector["error"]])
    return "~~~\n" + "\n".join(lines) + "\n~~~\n"


if __name__ == "__main__":
    os.makedirs(OUTPUT, exist_ok=True)
    markdown = []

    ml_bua_skem = [ml_bua_skem_vector(MLBUASKEM768()), ml_bua_skem_vector(MLBUASKEM1024())]
    with open(os.path.join(OUTPUT, "ml-bua-skem.json"), "w") as f:
        json.dump(to_json(ml_bua_skem), f, indent=2)
        f.write("\n")
    for vector in ml_bua_skem:
        markdown.append("### " + vector["name"] + "\n\n" + render_vector(vector))

    for identifier, generate in [("oquake-mlbuaskem1024", lambda i: [oquake_vector(i)]),
                                 ("oquakeplus-mlbuaskem1024-mlkem1024", lambda i: [oquakeplus_vector(i)]),
                                 ("cpaceoquake-x25519-mlbuaskem1024", lambda i: [cpaceoquake_vector(i)]),
                                 ("cpaceoquakeplus-x25519-mlbuaskem1024-xwing", cpaceoquakeplus_vectors)]:
        vectors = generate(identifier)
        with open(os.path.join(OUTPUT, identifier + ".json"), "w") as f:
            json.dump(to_json({"configuration": identifier, "vectors": vectors}), f, indent=2)
            f.write("\n")
        for vector in vectors:
            markdown.append("### " + vector["name"] + "\n\nConfiguration: `" + identifier + "`\n\n" + render_vector(vector))

    with open(os.path.join(OUTPUT, "test-vectors.md"), "w") as f:
        f.write("\n".join(markdown))

    for name in sorted(os.listdir(OUTPUT)):
        if name.endswith(".json"):
            check_replay(os.path.join(OUTPUT, name))
