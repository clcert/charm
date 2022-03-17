from charm.toolbox.pairinggroup import PairingGroup

from whotoopss import WhoTooPSS

k = 4
n = 6
group = PairingGroup('BN254')

WhoTooPSS(group, k, n)