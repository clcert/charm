from charm.toolbox.pairinggroup import PairingGroup

from util import User
from whotoopss import WhoTooPSS

k = 4
n = 6
group = PairingGroup('BN254')

whotoo = WhoTooPSS(group, k, n)
user = User(0, n)

whotoo.issue(user)

print(user.id)
print(user.da_shares)
print(user.alpha)
print(user.R)
print(user.temp)