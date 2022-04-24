from charm.core.engine.util import (
    bytesToObject,
    objectToBytes
)
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

from secshare import SecShare

class Manager():

    """
    Scheme manager class

    mskit = (xit, gammait)
        xit : skeg_share
        gammait : skbbs_share

    Attributes
    ----------
    id : int
        Identifier of the manager.
    n : int
        Total number of managers.
    da_shares : list[:py:class:`pairing.Element`]
        Shares of user private key
    skeg_share : :py:class:`pairing.Element`
        Share of ElGamal secret key.
    skbbs_share : :py:class:`pairing.Element`
        Share of BBS secret key.
    skenc : :py:class:`nacl.public.PrivateKey`
        Secret key for encryption scheme.
    sksig : :py:class:`nacl.signing.SigningKey`
        Secret key for signing scheme.
    deltas : list[int]
        Coefficients of delta polynomial.
    epsilon : dict[int -> :py:class:`pairing.Element`]
        Commitments to delta coefficients
    time_step : int
        Current timestep of the scheme.
    """

    def __init__(self, id: int, n: int, ss: SecShare):
        self.id = id
        self.n = n
        self.da_shares = [0] * n
        self.sec_share = ss
        self.skeg_share = None
        self.skbbs_share = None
        self.skenc = PrivateKey.generate()
        self.sksig = SigningKey.generate()
        self.deltas = []
        self.epsilons = {}
        self.time_step = 0

        self.temp1 = None
        self.temp2 = None
        self.temp3 = None
        self.temp4 = None
        self.temp5 = None
        self.temp6 = None
        self.temp7 = None
        self.beaver = None
        self.gen = []


# ------------------- Getters -------------------- #
    def get_index(self) -> int:
        """
        Gets the manager's index for the secret sharing schemes

        Returns
        -------
        int
            Manager's index in the secret share polynomials.
        """
        return self.id

    def get_pkenc(self) -> PublicKey:
        """
        Gets the manager's encryption public key

        Returns
        -------
        :py:class:`nacl.public.PublicKey`
            Manager's public key
        """
        return self.skenc.public_key

    def get_pksig(self) -> bytes:
        """
        Get the manager's signing public key
        
        Returns
        -------
        bytes
            Manager's signing key
        """
        return self.sksig.verify_key.encode()

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

    def decrypt(self, cph: EncryptedMessage, spk: PublicKey) -> int:
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
        int
            Decrypted message.
        """
        b = Box(self.skenc, spk)
        rm = b.decrypt(cph)
        return int(rm.decode('utf-8'))

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

# ------------------- Initialization -------------------- #
    def gen_beaver(self, mgr_pk: dict) -> tuple:
        """
        Generates beaver triplets for every manager

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
        """
        pk, a, b, c = bev
        ai = self.decrypt(a[self.id], pk)
        bi = self.decrypt(b[self.id], pk)
        ci = self.decrypt(c[self.id], pk)
        self.beaver = (ai, bi, ci)

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
                dec_delta = self.decrypt(evals[i][self.id], mgr_pk[i])
                x_prime += dec_delta
                gamma_prime += dec_delta

        x_enc = self.encrypt(x_prime, r_pk)
        gamma_enc = self.encrypt(gamma_prime, r_pk)

        return (x_enc, gamma_enc)

    def reconstruct(self, x_shares: list, gamma_shares: list, mgr_pk: dict, k: int):
        """
        Reconstructs the shares of the manager's secret key

        Parameters
        ----------
        x_shares : dict[:py:class:`pairing.Element`->:py:class:`pairing.Element`]
            Shares of the that interpolate the share of ElGammal secret key.
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

            x = self.decrypt(x_shares[i], pk)
            gamma = self.decrypt(gamma_shares[i], pk)

            x_dec[key] = self.sec_share.group.init(ZR, x)
            gamma_dec[key] = self.sec_share.group.init(ZR, gamma)

        x = self.sec_share.reconstruct_d(x_dec, self.id, k)
        gamma = self.sec_share.reconstruct_d(gamma_dec, self.id, k)

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
            self.epsilons[m] = self.sec_share.g ** self.deltas[m]

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
        
        v = {"id": self.id, "time": self.time_step + 1, "epsilons": self.epsilons.copy(), "e": e.copy()}
        vs = {"id": self.id, "time": self.time_step + 1, "epsilons": self.epsilons.copy(), "e": e.copy()}

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
        for i in evals.keys():
            try:
                result = result and self.verify(mgr_vk[i], evals[i][1])
            except:
                return False
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
            if j != self.id:
                pkt = evals[j][0]
                u = self.decrypt(pkt["e"][self.id], mgr_pk[j])
                prod = 1
                for m in pkt["epsilons"].keys():
                    prod *= (pkt["epsilons"][m] ** (self.id ** m))
                result = result and (self.sec_share.g ** u == prod)
        
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
            u = self.decrypt(evals[j][0]["e"][self.id], mgr_pk[j])
            self.skeg_share += u
            self.skbbs_share += u

        self.time_step += 1