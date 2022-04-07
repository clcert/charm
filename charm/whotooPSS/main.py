from charm.toolbox.pairinggroup import PairingGroup

from manager import Manager
from util import User
from whotoopss import WhoTooPSS

k = 4
n = 6
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

user = User(0, n)
whotoo.issue(user)

msg = "Message to sign"
(c, sigma) = whotoo.sign(user, msg)
verified = whotoo.verify(msg, c, sigma)
print(verified)

id = whotoo.trace(msg, c, sigma)
if id == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {id}")

c = whotoo.managers[1].encrypt(12345, whotoo.managers[2].get_pkenc())
print(whotoo.managers[2].decrypt(c))

rpc = 3
mgr = Manager(rpc, n)
whotoo.recover(rpc, mgr)
whotoo.update()