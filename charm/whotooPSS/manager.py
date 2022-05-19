from charm.toolbox.pairinggroup import ZR
from json import dumps
from nacl.signing import (
    SignedMessage,
    SigningKey,
    VerifyKey
)
from nacl.public import (
    Box,
    PrivateKey,
    PublicKey
)
from nacl.utils import EncryptedMessage

from bbs import BBS
from secshare import SecShare
from util import (
    zklogeq,
    zklogeq_verify
)

class Manager():
    """
    Scheme manager class

    mskit = (xit, gammait)
        xit : skeg_share
        gammait : skbbs_share

    Attributes
    ----------
    index : int
        Identifier of the manager.
    name : str
        Screen name of the manager.
    n : int
        Total number of managers.
    sec_share : :py:class:`secshare.SecShare`
        Secret share scheme.
    bbs : :py:class:`bbs.BBS`
        BBS signature scheme.
    skenc : :py:class:`nacl.public.PrivateKey`
        Secret key for encryption scheme.
    sksig : :py:class:`nacl.signing.SigningKey`
        Secret key for signing scheme.
    skeg_share : :py:class:`pairing.Element`
        Share of ElGamal secret key.
    pkeg : :py:class:`pairing.Element`
        ElGamal public key.
    skbbs_share : :py:class:`pairing.Element`
        Share of BBS secret key.
    pkbbs : :py:class:`pairing.Element`
        BBS public key.
    deltas : list[int]
        Coefficients of delta polynomial.
    epsilon : dict[int -> :py:class:`pairing.Element`]
        Commitments to delta coefficients
    time_step : int
        Current timestep of the scheme.
    beaver : tuple[:py:class:`pairing.Element`]
        Currect beaver triplet.
    """

    def __init__(self, id: int, n: int):
        self.index = id
        self.n = n
        self.sec_share = None
        self.bbs = None
        self.skenc = PrivateKey.generate()
        self.sksig = SigningKey.generate()
        self.skeg_share = None
        self.pkeg = None
        self.skbbs_share = None
        self.pkbbs = None

        self.deltas = []
        self.epsilons = {}
        self.time_step = 0
        self.beaver = None

        self.temp1 = None
        self.temp2 = None
        self.temp3 = None
        self.temp4 = None

# ------------------- Getters -------------------- #
    def get_index(self) -> int:
        """
        Gets the manager's index for the secret sharing schemes

        Returns
        -------
        int
            Manager's index in the secret share polynomials.
        """
        return self.index

    def get_pkenc(self) -> PublicKey:
        """
        Gets the manager's encryption public key

        Returns
        -------
        :py:class:`nacl.public.PublicKey`
            Manager's public key
        """
        return self.skenc.public_key

    def _get_skenc(self) -> bytes:
        """
        Gets the manager's encryption secret key

        Returns
        -------
        bytes
            Manager's public key
        """
        return self.skenc.encode()

    def get_pksig(self) -> bytes:
        """
        Get the manager's signing public key
        
        Returns
        -------
        bytes
            Manager's signing key
        """
        return self.sksig.verify_key.encode()

    def _get_sksig(self) -> bytes:
        """
        Gets the manager's signing secret key

        Returns
        -------
        bytes
            Manager's public key
        """
        return self.skenc.encode()

    def get_pkeg(self):
        """
        Get the manager's ElGamal public key

        Returns
        :py:class:`pairing.Element`
            Manager's ElGamal public key.
        """
        return self.pkeg

    def get_pkbbs(self):
        """
        Get the manager's BBS public key

        Returns
        :py:class:`pairing.Element`
            Manager's BBS public key.
        """
        return self.pkbbs

# ------------------- Encryption -------------------- #
    def encrypt(self, msg: int, rpk: PublicKey) -> EncryptedMessage:
        """
        Encrypts a message for the specified recipient

        Parameters
        ----------
        msg : int
            Message to be encrypted.
        rpk : :py:class:`nacl.public.PublicKey`
            Recipient's public key.

        Returns
        -------
        :py:class:`nacl.utils.EncryptedMessage`
            Encryption of the message.
        """
        b = Box(self.skenc, rpk)
        m = bytes(str(msg), 'utf-8')
        return b.encrypt(m)

    def decrypt(self, cph: EncryptedMessage, spk: PublicKey) -> str:
        """
        Decrypts a message intended to the manager

        Parameters
        ----------
        cph : :py:class:`nacl.utils.EncryptedMessage`
            Ciphertext.
        spk : :py:class:`nacl.public.PublicKey`
            Sender's public key.

        Returns
        -------
        str
            Decrypted message as utf-8 string.
        """
        b = Box(self.skenc, spk)
        rm = b.decrypt(cph)
        return rm.decode('utf-8')

# ------------------- Signature -------------------- #
    def sign(self, msg: str) -> SignedMessage:
        """
        Signs a string

        Parameters
        ----------
        msg : str
            Message to be signed.
        
        Returns
        -------
        :py:class:`nacl.signing.SignedMessage`
            Signature of the message.
        """
        m = bytes(msg, 'utf-8')
        return self.sksig.sign(m)

    def verify(self, spk, sigma) -> bool:
        """
        Verifies a signature

        Parameters
        ----------
        spk : dict
            Signer's public key.
        msg : str
            Signed message.
        sgn : str
            Sirgnature of the message.

        Returns
        -------
        bool
            True if the siganture is valid
        """
        ver = VerifyKey(spk)
        return ver.verify(sigma)

# ------------------- Copying -------------------- #
    def copy_2_1(self):
        """
        Copies the share at temp2 to temp1
        """
        self.temp1 = self.temp2

    def copy_2_4(self):
        """
        Copies the share at temp2 to temp4
        """
        self.temp4 = self.temp2

# ------------------- Initialization -------------------- #
    def init_schemes(self, group, g1, g2, k, pkeg, pkbbs):
        """
        Initializes the secret share scheme.
        """
        self.sec_share = SecShare(group, g1, g2, k, self.n)
        self.sec_share.h = pkeg["h"]
        self.bbs = BBS(group, g1, g2, pkeg["h"], pkbbs, self.sec_share)

    def gen_beaver(self, mgr_pk: dict) -> tuple:
        """
        Generates beaver triplets for every manager

        Parameters
        ----------
        mgr_pk : dict[:py:class:`nacl.public.PublicKey`]
            Public keys of the managers.

        Returns
        -------
        tuple[dict]
            Shares of the beaver triplets.
        """
        rbv = self.sec_share.group.random(ZR)
        a = self.sec_share.group.random(ZR)
        b = self.sec_share.group.random(ZR)
        c = a * b

        wa, _ = self.sec_share.gen_pedersen(a, rbv)
        wb, _ = self.sec_share.gen_pedersen(b, rbv)
        wc, _ = self.sec_share.gen_pedersen(c, rbv)

        ea = {}
        eb = {}
        ec = {}

        for i in range(1, self.n + 1):
            ea[i] = self.encrypt(wa[i][0], mgr_pk[i])
            eb[i] = self.encrypt(wb[i][0], mgr_pk[i])
            ec[i] = self.encrypt(wc[i][0], mgr_pk[i])

        return (self.get_pkenc(), ea, eb, ec)

    def set_beaver(self, bev: tuple):
        """
        Decrypts the shares of a beaver triplet from the public ledger

        Parameters
        ----------
        bev : tuple
            Shares of the beaver triplets.
        """
        pk, a, b, c = bev
        ai = int(self.decrypt(a[self.index], pk))
        bi = int(self.decrypt(b[self.index], pk))
        ci = int(self.decrypt(c[self.index], pk))
        self.beaver = (ai, bi, ci)

    def commit_gen(self, mgr_pk: dict) -> dict:
        """
        Commit the shares a secret sharing

        Parameters
        ----------
        mgr_pk : dict[:py:class:`nacl.public.PublicKey`]
            Public keys of the managers.

        Returns
        -------
        dict
            Dictionary containing the encrypted shares and the corresponding commitments.
        """
        z = self.sec_share.group.random(ZR)
        r = self.sec_share.group.random(ZR)
        w, v, vf = self.sec_share.gen_pedersen(z, r, feldman=True)
        
        shares = {}
        for j in range(1, self.n + 1):
            shares[j] = self.encrypt(w[j], mgr_pk[j])

        return {"shares": shares, "feldman": vf, "pedersen": v}

    def gen_sk(self, com_sh: dict, mgr_pk: dict):
        """
        Computes the share of the secret key

        Parameters
        ----------
        com_sh : dict[]
            Encrypted shares and commitments.
        mgr_pk : dict[:py:class:`nacl.public.PublicKey`]
            Public keys of the managers.
        """
        self.temp2 = 0
        i = self.index
        for j in range(1, self.n + 1):
            dec = self.decrypt(com_sh[j]["shares"][i], mgr_pk[j])
            sj, rj = map(int, dec[1:-1].split(","))
            if i != j:
                vf = com_sh[j]["feldman"]
                vp = com_sh[j]["pedersen"]
                verf = self.sec_share.verify_feldman(sj, vf, i)
                verp = self.sec_share.verify_pedersen(sj, rj, vp, i)
                if not (verf and verp):
                    raise Exception(f"Manager {i} failed to verify the commitment of manager {j}")
            self.temp2 += self.sec_share.group.init(ZR, sj)

    def set_skeg(self):
        """
        Sets the ElGamal secret key as the share stored in temp2
        """
        self.skeg_share = self.temp2

    def set_pkeg(self, com_sh: dict):
        """
        Sets the public key of ElGamal

        Parameters
        ----------
        com_sh : dict
        """
        h = self.sec_share.group.init(ZR, 1)
        for j in range(1, self.n + 1):
            h *= com_sh[j]["feldman"][0]
        self.sec_share.h = h
        self.bbs.v = h
        self.pkeg = {"g": self.sec_share.g1, "h": h}

    def set_skbbs(self):
        """
        Sets the BBS secret key as the share stored in temp2
        """
        self.skbbs_share = self.temp2

    def commit_exp(self, b) -> dict:
        """
        Commits the shares corresponding to b ^ temp1

        Parameters
        ----------
        b : :py:class:`pairing.Element`
            Base for the calculation.

        Returns
        -------
        dict
            Dictionary containg b^temp1, g1^temp1 and a zkproof.
        """
        bs = b ** self.temp1
        gs = self.sec_share.g1 ** self.temp1
        proof = zklogeq(self.sec_share.group, self.sec_share.g1, b, self.temp1)
        return {"b": b, "bs": bs, "gs": gs, "proof": proof}

    def verify_exp(self, exp_sh: dict):
        """
        Verifies that the shares of b^temp1 are consistent with its commitments

        Parameters
        ----------
        com_sh : dict
            Shares of b^temp_1 and its commitments.
        """
        i = self.index
        for j in range(1, self.n + 1):
            if i != j:
                es = exp_sh[j]
                a, c, t = es["proof"]
                ver = zklogeq_verify(self.sec_share.g1, es["b"], es["gs"], es["bs"], a, c, t)
                if not ver:
                    raise Exception(f"Manager {i} failed to verify {j}'s commitmet")

    def pool_exp(self, exp_sh):
        """
        Pools the result of of a distributed exponentiation

        Parameters
        ----------
        com_sh : dict
            Shares of b^temp_1 and its commitments.
        
        Returns
        -------
        :py:class:`pairing.Element`
            Result of the exponentiation.
        """
        r = self.sec_share.group.init(ZR, 1)
        for j in range(1, self.n + 1):
            bs = exp_sh[j]["bs"]
            jp = self.sec_share.group.init(ZR, j)
            r *= (bs ** self.sec_share.coeffs[jp])
        return r

    def set_pkbbs(self, exp_sh: dict):
        """
        Computes the public key for the BBS scheme

        Parameters
        ----------
        com_sh : dict
            Shares of b^temp_1 and its commitments.
        """
        self.pkbbs = self.pool_exp(exp_sh)
        self.bbs.w = self.pkbbs

# ------------------- Issue -------------------- #
    def mul_shares(self) -> tuple:
        """
        Creates a share to determin the product between temp1 and temp2

        Returns
        -------
        tuple
            Values of temp1 and temp2 minus beaver factors.
        """
        a, b, _ = self.beaver
        x = self.temp1
        y = self.temp2
        d = x - a
        e = y - b
        return (d, e)

    def pool_mul(self, mul_sh: dict):
        """
        Computes a share temp3 equivalent to the multiplication of the secrets shared in temp1 and temp2

        Parameters
        ----------
        mul_sh : dict
            temp1 and temp2 minus beaver factors of all managers.

        Returns
        -------
        :py:class:`pairing.Element`
            Share of the multiplication.
        """
        d_shares = {}
        e_shares = {}
        for j in range(1, self.n + 1):
            d, e = mul_sh[j]
            jp = self.sec_share.group.init(ZR, j)
            d_shares[jp] = d
            e_shares[jp] = e
        
        d_rec = self.sec_share.reconstruct(d_shares)
        e_rec = self.sec_share.reconstruct(e_shares)

        _, _, c = self.beaver
        x = self.temp1
        y = self.temp2
        self.temp3  = c + (x * e_rec) + (y * d_rec) - (e_rec * d_rec)
        return self.temp3

    def invert(self, winv):
        """
        Puts in temp1 the share corresponding to the inverse of the secret shares in temp2

        Parameters
        ----------
        winv : :py:class:`pairing.Element`
            Invertion factor.
        """
        self.temp1 = self.temp2 * winv

    def get_alpha(self, pkenc: PublicKey) -> EncryptedMessage:
        """
        Computes the shares of the secret signing key for the user
        
        Paramenters
        -----------
        pk_enc : :py:class:`nacl.public.PublicKey`
            User's public key.

        Returns
        -------
        :py:class:`nacl.utils.EncryptedMessage`
            Encrypted share.
        """
        alpha = self.temp4 - self.skbbs_share
        return self.encrypt(alpha, pkenc)

    def reconstruct(self, shares: dict):
        """
        A proxy for secret share's reconstruct method

        Parameters
        ----------
        shares : dict
            Shares of a secret.

        Returns
        -------
        :py:class:`pairing.Element`
            Reconstructed value.
        """
        return self.sec_share.reconstruct(shares)

# ------------------- Delta Polynomial -------------------- #
    def gen_delta(self, x: int, k: int):
        """
        Computes delta coefficients so the polinomial crosses at x
        
        Parameters
        ----------
        x : int
            Point where the polynomial crosses the x axis.
        k : int
            Degree of the polinomial.
        group : PairingGroup
            Pairing group.
        """
        deltas = [0] * k
        for i in range(1, k):
            deltas[i] = self.sec_share.group.random(ZR)
            deltas[0] -= deltas[i] * (x ** i)
        self.deltas = deltas

    def eval_d(self, x: int) -> int:
        """
        Evaluation of the delta polynomial at x

        Parameters
        ----------
        x : int
            Evaluation point.

        Returns
        -------
        int
            Evaluation result.
        """
        result = 0
        k = len(self.deltas)
        for i in range(0, k):
            result += self.deltas[i] * (x ** i)
        return result

# ------------------- Recovery -------------------- #
    def pub_evals_rec(self, r: int, mgr_pk: dict) -> list:
        """
        Publish the delta coefficients

        Parameters
        ----------
        r : int
            Identifier of the replaced manager.
        mgr_pk : list[dict]
            Public keys of all the managers.

        Returns
        -------
        list[dict]
            Encrypted delta coefficients.
        """
        evals = {}
        for i in range(1, self.n + 1):
            if i != r:
                pkt = self.encrypt(self.eval_d(i), mgr_pk[i])
                evals[i] = pkt
        return evals

    def comp_shares(self, evals: dict, mgr_pk: dict, r_pk: PublicKey, r: int) -> tuple:
        """
        Calculates the shares of the new manager's secret key

        Parameters
        ----------
        evals : dict[list[bytes]]
            Encryption of the delta evaluations published by all managers.
        mgr_pk : dict[:py:class:`nacl.public.PublicKey`]
            Public keys of the managers.
        r_pk : :py:class:`nacl.public.PublicKey`
            Public key of the new manager.
        r : int
            Identity of the manager being replaced.
        group : PairingGroup
            Pairing group.

        Returns
        -------
        list[:py:class:`pairing.Element`]
            Encrypted share of the new manager's secret key.
        """
        x_prime = self.skeg_share
        gamma_prime = self.skbbs_share

        for i in range(1, self.n + 1):
            if i != r:
                dec_delta = int(self.decrypt(evals[i][self.index], mgr_pk[i]))
                x_prime += dec_delta
                gamma_prime += dec_delta

        x_enc = self.encrypt(x_prime, r_pk)
        gamma_enc = self.encrypt(gamma_prime, r_pk)

        return (x_enc, gamma_enc)

    def reconstruct_keys(self, x_shares: list, gamma_shares: list, mgr_pk: dict, k: int):
        """
        Reconstructs the shares of the manager's secret key

        Parameters
        ----------
        x_shares : dict[:py:class:`pairing.Element`->:py:class:`pairing.Element`]
            Shares of the that interpolate the share of ElGamal secret key.
        gamma_shares : dict[:py:class:`pairing.Element`->:py:class:`pairing.Element`]
            Shares of the that interpolate the share of BBS secret key.
        mgr_pk : dict[int->:py:class:`nacl.public.PublicKey`]
            Public keys of all the managers.
        ss : :py:class:`secshare.SecShare`
            Secret sharing scheme.
        k : int
            Degree of the delta polynomial.
        """
        x_dec = {}
        gamma_dec = {}

        for i in x_shares.keys():
            pk = mgr_pk[i]
            key = self.sec_share.group.init(ZR, i)

            xi = int(self.decrypt(x_shares[i], pk))
            gammai = int(self.decrypt(gamma_shares[i], pk))

            x_dec[key] = self.sec_share.group.init(ZR, xi)
            gamma_dec[key] = self.sec_share.group.init(ZR, gammai)

        x = self.sec_share.reconstruct_d(x_dec, self.index, k)
        gamma = self.sec_share.reconstruct_d(gamma_dec, self.index, k)

        print(f"x_rec      : {x}")
        print(f"gamma_rec  : {gamma}")

        self.skeg_share = x
        self.skbbs_share = gamma

# ------------------- Update -------------------- #
    def gen_epsilon(self):
        """
        Computes the epsilon commitments
        """
        k = len(self.deltas)
        for m in range(0, k):
            self.epsilons[m] = self.sec_share.g1 ** self.deltas[m]

    def pub_evals_upd(self, mgr_pk: dict) -> tuple:
        """
        Evaluates the delta polynomial for every manager, then encrypts and sign the result.

        Parameters
        ----------
        mgr_pk : dict[int->:py:class:`nacl.public.PublicKey`]
            Public keys of all the managers.

        Returns
        -------
        tuple[dict, :py:class:`nacl.signing.SignedMessage`]
            Sidned dictionary including the identity of the manager, following time step, 
            epsilon commitments and encrypted delta evaluations.
        """
        e = {}
        for i in mgr_pk.keys():
            e[i] = self.encrypt(self.eval_d(i), mgr_pk[i])
        
        v = {"time": self.time_step + 1, "epsilons": self.epsilons.copy(), "e": e.copy()}
        vs = {"time": self.time_step + 1, "epsilons": self.epsilons.copy(), "e": e.copy()}

        for i in vs["epsilons"].keys():
            vs["epsilons"][i] = str(vs["epsilons"][i])

        for i in vs["e"].keys():
            vs["e"][i] = str(vs["e"][i])
        
        vjson = dumps(vs)
        sigma = self.sign(vjson)

        return (v, sigma)

    def verify_sigs(self, evals: dict, mgr_vk: dict) -> bool:
        """
        Verifies the signatures of the update packets

        Parameters
        ----------
        evals : dict
            Update packets commited by all managers.

        Returns
        -------
        bool
            True if every signature is verified.
        """
        result = True
        for j in evals.keys():
            try:
                result = result and self.verify(mgr_vk[j], evals[j][1])
            except:
                raise Exception(f"Manager {self.index} found {j}'s signature to be invalid")
        return result

    def verify_upd(self, evals: dict, mgr_pk: dict) -> bool:
        """
        Verifies the correctness of the update packet contents

        Parameters
        ----------
        evals : dict
            Update packets commited by all managers.

        Returns
        -------
        bool
            True if the contents of the packets are consistent.
        """
        result = True
        for j in evals.keys():
            if j != self.index:
                pkt = evals[j][0]
                u = int(self.decrypt(pkt["e"][self.index], mgr_pk[j]))
                prod = 1
                for m in pkt["epsilons"].keys():
                    prod *= (pkt["epsilons"][m] ** (self.index ** m))
                result = result and (self.sec_share.g1 ** u == prod)
        
        return result

    def update_shares(self, evals: dict, mgr_pk: dict):
        """
        Adds up the recieved delta evaluations to update the secret keys
        
        Parameters
        ----------
        evals : dict
            Dictionary containing the encrypted evaluations of all deltas.
        mgr_pk : dict[int->:py:class:`nacl.public.PublicKey`]
            Public keys of all the managers.
        """
        for j in evals.keys():
            u = int(self.decrypt(evals[j][0]["e"][self.index], mgr_pk[j]))
            self.skeg_share += u
            self.skbbs_share += u

        self.time_step += 1

# ------------------- Trace -------------------- #
    def set_trace_key(self):
        """
        Puts the share of the ElGamal secret key into temp1
        """
        self.temp1 = self.skeg_share