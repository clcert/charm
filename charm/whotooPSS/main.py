from charm.toolbox.pairinggroup import PairingGroup

from manager import Manager
from user import User
from whotoopss import WhoTooPSS

k = 4
n = 8
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

for i in range(1, n+1):
    mgr = Manager(i, n)
    print(mgr._get_skenc())
    whotoo.add_manager(mgr)

whotoo.gen_beaver()
whotoo.init_elgamal()
whotoo.init_bbs()

user = User(0, n)
user.init_schemes(group, whotoo.g1, whotoo.g2, k, whotoo.pkeg, whotoo.pkbbs)
whotoo.issue(user)

print("--- Signature verification ---")
verifier = User(2, n)
verifier.init_schemes(group, whotoo.g1, whotoo.g2, k, whotoo.pkeg, whotoo.pkbbs)
msg = "Message to sign"
(c, sigma) = whotoo.sign(user, msg)
verified = whotoo.verify(verifier, msg, c, sigma)
print(verified)

print("--- Signature tracing ---")
id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")

print("--- Manager encryption ---")
cph = whotoo.managers[1].encrypt(12345, whotoo.managers[2].get_pkenc())
print(whotoo.managers[2].decrypt(cph, whotoo.managers[1].get_pkenc()))

print("--- Manager replacement ---")
rpc = 3
mgr = Manager(rpc, n)
mgr.init_schemes(group, whotoo.g1, whotoo.g2, k, whotoo.pkeg, whotoo.pkbbs)
whotoo.recover(rpc, mgr)
whotoo.update()

user1 = User(1, n)
user1.init_schemes(group, whotoo.g1, whotoo.g2, k, whotoo.pkeg, whotoo.pkbbs)
whotoo.issue(user1)

id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")

(c, sigma) = whotoo.sign(user1, msg)
verified = whotoo.verify(verifier, msg, c, sigma)
print(verified)

id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")