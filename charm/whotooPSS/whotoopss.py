from re import I
from charm.toolbox.hash_module import Hash
from charm.toolbox.pairinggroup import (
    G1,
    G2,
    PairingGroup,
    ZR
)
import numpy as np
from tqdm.contrib.concurrent import thread_map

from bbs import BBS
from elgamal import ElGamal
from manager import Manager
from secshare import SecShare
from util import (
    User
)

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

        self.mgr_pk = {}
        self.mgr_vk = {}
        self.id_map = {}
        
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        self.k = k
        self.n = n

        self.eg = ElGamal(self.group)
        self.sec_share = SecShare(self.group, self.g1, self.g2, self.k, self.n, self.eg)
        self.sec_share.h = self.group.random(G1) #temp

        #initialize managers
        self.managers = []
        self.beaver = []
        for i in range(1, n+1):
            mgr = Manager(i, n, self.sec_share)
            self.managers.append(mgr)
            self.mgr_pk[i] = mgr.get_pkenc()
            self.mgr_vk[i] = mgr.get_pksig()
        
        for p in self.managers:
            self.beaver.append(p.gen_beaver(self.mgr_pk))

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

    def add_manager(self, mgr: Manager):
        i = mgr.get_index()
        assert (i > self.n), "Invalid manager index"
        self.mgr_pk[i] = mgr.get_pkenc()
        self.mgr_vk[i] = mgr.get_pksig()

    def issue(self, user: User):
        """
        Issuing of user key

        Parameters
        ----------
        user : :py:class:`util.User`
            User requesting a signing key.
        """
        if not self.beaver:
            for p in self.manager:
                self.beaver.append(p.gen_beaver(self.mgr_pk))
        bev = self.beaver.pop()
        for p in self.managers:
            p.set_beaver(bev)
        # A = r
        self.managers, r = self.bbs.key_issue(self.managers, user)
        self.id_map[r] = user

    def recover(self, id, mgr):
        """
        Replaces the selected manager with a new one

        Parameters
        ----------
        id : int
            Identity of the manager to be replaced.
        mgr : :py:class:`util.Manager`
            New manager to be included.
        """
        mgr.beaver = self.managers[id-1].beaver
        evals = {}

        for p in self.managers:
            if p.id != id:
                p.gen_delta(id, self.k)
                evals[p.id] = p.pub_evals_rec(id, self.mgr_pk)

        x_shares = {}
        gamma_shares = {}

        for p in self.managers:
            if p.id != id:
                xi, gammai = p.comp_shares(evals, self.mgr_pk, mgr.get_pkenc(), id)
                x_shares[p.id] = xi
                gamma_shares[p.id] = gammai

        mgr.reconstruct(x_shares, gamma_shares, self.mgr_pk, self.k)

        print(f"x_orig     : {self.managers[id-1].skeg_share}")
        print(f"gamma_orig : {self.managers[id-1].skbbs_share}")

        self.managers[id-1] = mgr
        self.mgr_pk[id] = mgr.get_pkenc()
        self.mgr_vk[id] = mgr.get_pksig()

    def update(self):
        """
        Update the shares of the managers' secret keys

        Parameters
        ----------
        """
        enc_u = {}

        for p in self.managers:
            p.gen_delta(0, self.k)
            p.gen_epsilon()
            enc_u[p.id] = p.pub_evals_upd(self.mgr_pk)

        for p in self.managers:
            if not p.verify_sigs(enc_u, self.mgr_vk):
                print("Found invalid signature, interrupting process...")
                return

            if not p.verify_upd(enc_u, self.mgr_pk):
                print("Packet contents are inconsistent, interrupting process...")
                return

        self.beaver = []

        for p in self.managers:
            p.update_shares(enc_u, self.mgr_pk)
            self.beaver.append(p.gen_beaver(self.mgr_pk))

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