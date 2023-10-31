import requests
import commons

with open("keys/root.public", "r") as f:
    fpf_key = f.read()

with open("keys/intermediate.public", "r") as f:
    nr_key = f.read()

with open("keys/intermediate.sig", "r") as f:
    nr_sig = f.read()

res = requests.post(f"http://{commons.SERVER}/keys", json={"fpf_key": fpf_key, "newsroom_key": nr_key, "newsroom_sig": nr_sig})

assert(res.status_code == 200)
