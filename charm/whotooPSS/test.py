from charm.toolbox.pairinggroup import (
    PairingGroup,
    ZR
)

from manager import Manager
from util import User
from whotoopss import WhoTooPSS

k = 8
n = 10
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

def f(x: int) -> int:
    res = x
    for i in range(2, k + 1):
        res += i * (x ** i)
    return res

def d(x: int, coefs: dict) -> int:
    res = 0
    for i in range(0, len(coefs)):
        res += coefs[i] * (x ** i)
    return res

shares = {}
for p in whotoo.managers:
    shares[p.id] = f(p.id)

print(f"f : {shares}")

q = whotoo.group.order()

for i in range(0, 8):
    sec = whotoo.sec_share.reconstruct_d(shares, i, q, k)
    #print(f"{i} : {sec}")

for i in range(1, n + 1):
    shares_i = shares.copy()
    shares_i.pop(i, None)
    sec = whotoo.sec_share.reconstruct_d(shares_i, i, q, k)
    if sec > q/2:
        sec -= q
    print(f"{i} poping ({i}, y): {sec}")

deltas = [0] * k
for i in range(1, k):
    deltas[i] = int(whotoo.group.random(ZR))
    deltas[0] -= deltas[i] * (4 ** i)
deltas[0] = whotoo.group.init(ZR, deltas[0])

diff = {}
for p in whotoo.managers:
    diff[p.id] = d(p.id, deltas)

#print(f"delta : {diff}")