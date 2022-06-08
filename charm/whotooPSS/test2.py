from charm.toolbox.pairinggroup import PairingGroup, G1
from base64 import (
    b64encode,
    b64decode
)

from manager import Manager
from whotoopss import WhoTooPSS

k = 2
n = 3
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

for i in range(1, n+1):
    mgr = Manager(i, n)
    whotoo.add_manager(mgr)

whotoo.init_elgamal()

group1 = PairingGroup("BN254")
g1 = whotoo.g1
g1e = whotoo.group.serialize(g1)
g1se = b64encode(g1e).decode("utf-8")
g1sd = b64decode(g1se.encode("utf-8"))
g1d = group1.deserialize(g1sd)

print(f"g1 {g1}")
print(f"g1d {g1d}")

g1 = whotoo.g2
g1e = whotoo.group.serialize(g1)
g1se = b64encode(g1e).decode("utf-8")
g1sd = b64decode(g1se.encode("utf-8"))
g1d = group1.deserialize(g1sd)

print(f"g2 {g1}")
print(f"g2d {g1d}")

g1 = whotoo.pkeg["h"]
g1e = whotoo.group.serialize(g1)
g1se = b64encode(g1e).decode("utf-8")
g1sd = b64decode(g1se.encode("utf-8"))
g1d = group1.deserialize(g1sd)

print(f"h {g1}")
print(f"hd {g1d}")

whotoo.init_bbs()

