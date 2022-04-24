from charm.toolbox.pairinggroup import PairingGroup

from manager import Manager
from util import User
from whotoopss import WhoTooPSS

k = 4
n = 8
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

user = User(0, n)
whotoo.issue(user)

print("--- Signature verification ---")
msg = "Message to sign"
(c, sigma) = whotoo.sign(user, msg)
verified = whotoo.verify(msg, c, sigma)
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
mgr = Manager(rpc, n, whotoo.sec_share)
whotoo.recover(rpc, mgr)
whotoo.update()

user1 = User(1, n)
whotoo.issue(user1)

id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")

(c, sigma) = whotoo.sign(user1, msg)
verified = whotoo.verify(msg, c, sigma)
print(verified)

id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")