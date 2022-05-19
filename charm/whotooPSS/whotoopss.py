from ssl import HAS_TLSv1_1
from charm.toolbox.hash_module import Hash
from charm.toolbox.pairinggroup import (
    G1,
    G2,
    PairingGroup
)

from bbs import BBS
from manager import Manager
from secshare import SecShare
from user import User

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
    g1 : :py:class:`pairing.Element`
        Generator of the fist bilineal group.
    g2 : :py:class:`pairing.Element`
        Generator of the second bilineal group.
    k : int
        Secret sharing threshold.
    n : int
        Number of managers.
    pkeg : dict[str, :py:class:`pairing.Element`]
        Public key of ElGamal encryption.
    pkbss : :py:class:`pairing.Element`
        Public key of BBS scheme
    managers : dict[int, :py:class:`util.Server`]
        Current managers in the scheme (servers in WhoToo+).
    bev_st : list[tuple[:py:class:`pairing.Element`]]
        Stack of beaver triplet shares.
    mgr_pk : dict[int, :py:class:`nacl.public.PublicKey`]
        Public encryption key of each manager.
    mgr_vk : dict[int, :py:class:`nacl.signing.VerifyKey`]
        Signature verification key of each manager.
    user_id : dict[:py:class:`pairing.Element`, :py:class:`util.User`]
        Dictionary of users using thier public key A (R in WhoToo+).

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
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        self.k = k
        self.n = n

        h = self.group.random(G1) #temp
        self.pkeg = {"g": self.g1, "h": h}
        self.pkbbs = None

        self.managers = {}
        self.bev_st = []
        self.mgr_pk = {}
        self.mgr_vk = {}
        self.user_id = {}

    def add_manager(self, mgr: Manager):
        if len(self.managers.keys()) >= self.n:
            raise Exception("All manager positions are in use")
        i = mgr.get_index()
        if i > self.n:
            raise Exception("The index {i} is out of scope")
        if i in self.managers.keys():
            raise Exception(f"Manager index {i} is already in use")
        mgr.init_schemes(self.group, self.g1, self.g2, self.k, self.pkeg, self.pkbbs)
        self.managers[i] = mgr
        self.mgr_pk[i] = mgr.get_pkenc()
        self.mgr_vk[i] = mgr.get_pksig()

    def gen_beaver(self):
        if len(self.mgr_pk.keys()) < self.n:
            raise Exception("All manager public encryption keys are required")
        for p in self.managers.values():
            self.bev_st.append(p.gen_beaver(self.mgr_pk))

    def init_elgamal(self):
        """
        u = v^x : h = v^skeg
        """
        if len(self.mgr_pk.keys()) < self.n:
            raise Exception("All manager public encryption keys are required")
        com_sh = {}
        for p in self.managers.values():
            com_sh[p.get_index()] = p.commit_gen(self.mgr_pk)
        for p in self.managers.values():
            p.gen_sk(com_sh, self.mgr_pk)
            p.set_skeg()
        for p in self.managers.values():
            p.set_pkeg(com_sh)
        
        h = self.managers[1].get_pkeg()
        for p in self.managers.values():
            hi = p.get_pkeg()
            if h != hi:
                raise Exception(f"Response from manager {p.get_index()} doesn't match the first manager")
        self.pkeg = h

    def init_bbs(self):
        """
        w = g2^gamma : pkbss = g2^skbss
        """
        if len(self.mgr_pk.keys()) < self.n:
            raise Exception("All manager public encryption keys are required")
        com_sh = {}
        for p in self.managers.values():
            com_sh[p.get_index()] = p.commit_gen(self.mgr_pk)
        for p in self.managers.values():
            p.gen_sk(com_sh, self.mgr_pk)
            p.set_skbbs()
            p.copy_2_1()
        
        exp_sh = {}
        for p in self.managers.values():
            exp_sh[p.get_index()] = p.commit_exp(self.g2)
        for p in self.managers.values():
            p.verify_exp(exp_sh)
            p.set_pkbbs(exp_sh)
        h = self.managers[1].get_pkbbs()
        for p in self.managers.values():
            hi = p.get_pkbbs()
            if h != hi:
                raise Exception(f"Response from manager {p.get_index()} doesn't match the first manager")
        self.pkbbs = h

    def issue(self, user: User):
        """
        Issuing of user key

        Parameters
        ----------
        user : :py:class:`util.User`
            User requesting a signing key.
        """
        if not self.bev_st:
            self.gen_beaver()
        bev = self.bev_st.pop()
        for p in self.managers.values():
            p.set_beaver(bev)
        # A = r
        r = user.bbs.key_issue(user, self.managers, self.mgr_pk)
        self.user_id[r] = user

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
        evals = {}

        for p in self.managers.values():
            if p.get_index() != id:
                p.gen_delta(id, self.k)
                evals[p.get_index()] = p.pub_evals_rec(id, self.mgr_pk)

        x_shares = {}
        gamma_shares = {}

        for p in self.managers.values():
            if p.get_index() != id:
                xi, gammai = p.comp_shares(evals, self.mgr_pk, mgr.get_pkenc(), id)
                x_shares[p.get_index()] = xi
                gamma_shares[p.get_index()] = gammai

        mgr.reconstruct_keys(x_shares, gamma_shares, self.mgr_pk, self.k)

        print(f"x_orig     : {self.managers[id].skeg_share}")
        print(f"gamma_orig : {self.managers[id].skbbs_share}")

        self.managers[id] = mgr
        self.mgr_pk[id] = mgr.get_pkenc()
        self.mgr_vk[id] = mgr.get_pksig()

    def update(self):
        """
        Update the shares of the managers' secret keys

        Parameters
        ----------
        """
        enc_u = {}

        for p in self.managers.values():
            p.gen_delta(0, self.k)
            p.gen_epsilon()
            enc_u[p.get_index()] = p.pub_evals_upd(self.mgr_pk)

        for p in self.managers.values():
            if not p.verify_sigs(enc_u, self.mgr_vk):
                raise Exception(f"Manager {p.get_index()} found an invalid signature")

            if not p.verify_upd(enc_u, self.mgr_pk):
                raise Exception(f"Manager {p.get_index()} found the update commitments to be inconsistent")

        for p in self.managers.values():
            p.update_shares(enc_u, self.mgr_pk)
        
        self.bev_st = []
        self.gen_beaver()

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
        return user.sign(msg)

    def verify(self, verifier, m: str, c: tuple, sigma: tuple) -> bool:
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
        return verifier.bbs.verify(m, c, sigma)

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
        ver = True
        for p in self.managers.values():
            ver = ver and (self.verify(p, m, c, sigma))
        if ver:
            c1, c2 = c
            exp_sh = {}
            for p in self.managers.values():
                p.set_trace_key()
                exp_sh[p.get_index()] = p.commit_exp(c1)
            for p in self.managers.values():
                p.verify_exp(exp_sh)
            d = self.managers[1].pool_exp(exp_sh)
            for p in self.managers.values():
                di = p.pool_exp(exp_sh)
                if di != d:
                    raise Exception(f"Response from manager {p.get_index()} doesn't match the first manager")
            r = c2/d
            return self.user_id[r].id
        else:
            return -1