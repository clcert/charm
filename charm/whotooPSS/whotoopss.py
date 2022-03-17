from charm.toolbox.hash_module import Hash
from charm.toolbox.pairinggroup import (
    G1,
    G2,
    PairingGroup
)

from bbs import BBS
from elgamal import ElGamal
from secshare import SecShare

class WhoTooPSS():
    """
    Scheme class

    Attributes
    ----------
    group : :py:class:`charm.toolbox.pairinggroup.PairingGroup`
        Pairing group.
    hashfunc : :py:class:`charm.toolbox.hash_module.Hash`
        Hash function.
    g1 : :py:class:`pairing.Element`
        Generator of the fist bilineal group.
    g2 : :py:class:`pairing.Element`
        Generator of the second bilineal group.
    k : int
        Secret sharing threshold.
    n : int
        Number of managers.
    eg : :py:class:`elgamal.ElGamal`
        ElGamal encription.
    sec_share : :py:class:`secshare.SecShare`
        Secret share scheme.

    Methods
    -------
    issue()
        Issues a key pair to a memeber of the authorized group
    recover()
        Recovers a manager's key share in order to replace said manager
    update()
        Allows the new set of managers to update their key shares
    sign()
        Allows an authorized group memeber to generate a signature
    verify()
        Verifies that a signature was produced by a memeber of the authorized group
    trace()
        Traces a signature to its signer
    """

    def __init__(self, group: PairingGroup, k: int, n: int):

        self.group = group
        self.hashfunc = Hash(pairingElement=self.group)
        
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        self.k = k
        self.n = n

        self.eg = ElGamal(self.group)
        self.sec_share = SecShare(self.group, self.g1, self.g2, self.k, self.n, self.eg)

    def issue(self):
        pass

    def recover(self):
        pass

    def update(self):
        pass

    def sign(self):
        pass

    def verify(self):
        pass

    def trace(self):
        pass