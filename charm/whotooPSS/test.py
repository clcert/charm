from charm.toolbox.pairinggroup import PairingGroup

from manager import Manager
from util import User
from whotoopss import WhoTooPSS

k = 4
n = 6
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)

from random import randint
from charm.toolbox.pairinggroup import ZR

def f(x: int) -> int:
    return x + 2 * (x ** 2) + 3 * (x ** 3) + 4 * (x ** 4)

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

sec = whotoo.sec_share.reconstruct_d(shares, 0, q, 4)
print(f" 0 : {sec}")
sec = whotoo.sec_share.reconstruct_d(shares, 4, q, 4)
print(f" 4 : {sec}")
sec = whotoo.sec_share.reconstruct_d(shares, 5, q, 4)
print(f" 5 : {sec}")
sec = whotoo.sec_share.reconstruct_d(shares, 6, q, 4)
print(f" 6 : {sec}")
sec = whotoo.sec_share.reconstruct_d(shares, 7, q, 4)
print(f" 7 : {sec}")

shares_4 = shares
shares_4.pop(4, None)
sec = whotoo.sec_share.reconstruct_d(shares_4, 4, q, 4)
print(f" 4 poping (4, y): {sec}")

deltas = [0] * k
for i in range(1, k):
    deltas[i] = int(whotoo.group.random(ZR))
    deltas[0] -= deltas[i] * (4 ** i)
deltas[0] = whotoo.group.init(ZR, deltas[0])

diff = {}
for p in whotoo.managers:
    diff[p.id] = d(p.id, deltas)

print(f"delta : {diff}")