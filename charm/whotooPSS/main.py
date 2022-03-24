from charm.toolbox.pairinggroup import PairingGroup
from numpy import identity

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

identity = whotoo.trace(msg, c, sigma)
if identity == -1:
    print("Invalid signature")
else:
    print(f"Accuser identified as {identity}")