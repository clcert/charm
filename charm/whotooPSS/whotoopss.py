from charm.toolbox.hash_module import Hash
from charm.toolbox.pairinggroup import (
    G1,
    G2,
    PairingGroup,
    ZR
)
from tqdm.contrib.concurrent import thread_map

from bbs import BBS
from elgamal import ElGamal
from secshare import SecShare
from util import (
    Manager,
    User
)
from wtset import PrivateMultiset

class WhoTooPSS():
    """
    Scheme class

    gpk = (v, u, g1, g2, w)
        v : pkeg[g]
        u : pkeg[h]
        g1 : g1
        g2 : g2
        w : pkbbs

    Attributes
    ----------
    group : :py:class:`charm.toolbox.pairinggroup.PairingGroup`
        Pairing group.
    hash_func : :py:class:`charm.toolbox.hash_module.Hash`
        Hash function.
    users : list[:py:class:`util.User`]
        Users registered in the scheme (valid accusers in WhoToo+).
    id_map : dict[:py:class:`pairing.Element`, :py:class:`util.User`]
        Dictionary of users using thier public key A (R in WhoToo+).
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
    managers: list[:py:class:`util.Server`]
        Current managers in the scheme (servers in WhoToo+).
    pkeg : dict[str, :py:class:`pairing.Element`]
        Public key of ElGamal encryption.
    pkbss : :py:class:`pairing.Element`
        Public key of BBS scheme
    bbs : :py:class:`bbs.BBS`
        Boneh Boyen Shachum signature scheme.
    mset : :py:class:`wtset.PrivateMultiset`
        Private multiset class.
    wtset : list[tuple[:py:class:`pairing.Element`]]
        ElGamal cipher of v (base for x secret share)

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
        self.hash_func = Hash(pairingElement=self.group)

        self.users = []
        self.id_map = {}
        
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        self.k = k
        self.n = n

        self.eg = ElGamal(self.group)
        self.sec_share = SecShare(self.group, self.g1, self.g2, self.k, self.n, self.eg)
        self.sec_share.h = self.group.random(G1) #temp

        # initialize Beaver's triples
        rbv = self.group.random(ZR)
        a = self.group.random(ZR)
        b = self.group.random(ZR)
        c = a * b
        wa, _ = self.sec_share.gen_pedersen(a, rbv)
        wb, _ = self.sec_share.gen_pedersen(b, rbv)
        wc, _ = self.sec_share.gen_pedersen(c, rbv)

        #initialize managers
        self.managers = []
        for i in range(1, n+1):
            man = Manager(i, n)
            man.beaver = (wa[i][0], wb[i][0], wc[i][0])
            self.managers.append(man)

        self.sec_share.managers = self.managers

        #initialize ElGamal keys
        #u = v^x
        h = self.sec_share.geng()
        self.sec_share.h = h
        self.pkeg = {'g': self.g1, 'h': h}

        def temp_func1(p):
            p.skeg_share = p.temp2

        thread_map(temp_func1, self.managers, leave=False)

        #initialize BBS keys
        self.sec_share.gen()

        def temp_func2(p):
            p.temp1 = p.temp2
            p.skbbs_share = p.temp2

        thread_map(temp_func2, self.managers, leave=False)
        # w = g2^gamma
        self.pkbbs = self.sec_share.exp(self.g2)

        self.bbs = BBS(self.group, self.g1, self.g2, self.pkeg['h'], self.pkbbs, self.sec_share)
        self.mset = PrivateMultiset(self.sec_share, self.eg, self.pkeg)

        self.wtset = self.mset.initialize()

    def issue(self, user: User):
        """
        Issuing of user key

        Parameters
        ----------
        user : :py:class:`util.User`
            User requesting a signing key.
        """
        # A = r
        self.managers, r = self.bbs.key_issue(self.managers, user)
        self.id_map[r] = user
        self.users.append(user)

    def recover(self):
        pass

    def update(self):
        pass

    def sign(self, user: User, msg: str) -> "tuple[tuple]":
        """
        Signing of message

        Parameters
        ----------
        user : :py:class:`util.User`
            Signer user.
        msg : str
            Message to be signed.
        
        Returns
        -------
        tuple[tuple[:py:class:`pairing.Element`]]
            Signature of the message.
        """
        return self.bbs.sign((user.R, user.alpha), msg)

    def verify(self, m: str, c: tuple, sigma: tuple) -> bool:
        """
        Verifies that the signature is valid to the user group

        Parameters
        ----------
        m : str
            Message to sign.
        c : tuple[:py:class:`pairing.Element`]
            ElGamal encryption of the signers public key.
        sigma : tuple[:py:class:`pairing.Element`]
            Signature of the message.

        Returns
        -------
        bool
            True if the signature is valid and was produced by a
            user of the scheme, False if not
        """
        return self.bbs.verify(m, c, sigma)

    def trace(self, m: str, c: tuple, sigma: tuple) -> int:
        """
        Traces the signer of a given message

        Parameters
        ----------
        m : str
            Signed message.
        c : tuple[:py:class:`pairing.Element`]
            ElGamal encryption of the signers public key.
        sigma : tuple[:py:class:`pairing.Element`]
            Signature of the message.

        Returns
        -------
        int
            Identity of the signer or -1 if the signature is invalid
        """
        if self.verify(m, c, sigma):
            r = self.sec_share.dist_dec(c)
            return self.id_map[r].id
        else:
            return -1