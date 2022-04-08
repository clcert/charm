from charm.schemes.pkenc.pkenc_rsa import RSA_Enc
from charm.schemes.pksig.pksig_rsa_hw09 import (
    SHA1,
    Sig_RSA_Stateless_HW09
)
from charm.toolbox.pairinggroup import ZR
from json import dumps

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
        Shares of distributed authority commitment.
    skeg_share : :py:class:`pairing.Element`
        Share of ElGamal secret key.
    skbbs_share : :py:class:`pairing.Element`
        Share of BBS secret key.
    enc : :py:class:`charm.schemes.pkenc.pkenc_cs98.CS98`
        Public key encryption scheme.
    pkenc : dict
        Public key for encryption.
    skenc : dict
        Secret key for encryption.
    deltas : dict[int]
        Delta coefficients.
    """

    def __init__(self, id: int, n: int):
        self.id = id
        self.n = n
        self.da_shares = [0] * n
        self.skeg_share = None
        self.skbbs_share = None
        self.enc = RSA_Enc()
        (self.pkenc, self.skenc) = self.enc.keygen()
        self.sig = Sig_RSA_Stateless_HW09()
        (self.pksig, self.sksig) = self.sig.keygen()
        self.temp1 = None
        self.temp2 = None
        self.temp3 = None
        self.temp4 = None
        self.temp5 = None
        self.temp6 = None
        self.temp7 = None
        self.beaver = None
        self.gen = []
        self.deltas = []
        self.epsilons = {}
        self.time_step = 0

    def get_pkenc(self) -> dict:
        """
        Gets the managers encryption public key

        Returns
        -------
        dict
            Manager's public key
        """
        return self.pkenc

    def encrypt(self, msg: int, rpk: dict) -> dict:
        """
        Encrypts a message for the specified recipient

        Parameters
        ----------
        msg : int
            Message to be encrypted.
        rpk : int
            Recipient's public key.

        Returns
        -------
        dict
            Encryption of the message.
        """
        m = bytes(str(msg), 'utf-8')
        return self.enc.encrypt(rpk, m)

    def decrypt(self, cph: dict) -> int:
        """
        Decrypts a message intended to the manager

        Parameters
        ----------
        cph : dict
            Ciphertext.

        Returns
        -------
        int
            Decrypted message.
        """
        rm = self.enc.decrypt(self.pkenc, self.skenc, cph)
        return int(rm.decode('utf-8'))

    def sign(self, msg: str) -> dict:
        """
        Signs a string

        Parameters
        ----------
        msg : str
            Message to be signed.
        
        Returns
        -------
        dict
            Signature of the message.
        """
        h = SHA1(bytes(msg, 'utf-8'))
        self.sig.sign(self.pksig, self.sksig, h)

    def verify(self, spk: dict, msg: str, sgn: str) -> bool:
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
        return self.sig.verify(spk, msg, sgn)

    def gen_delta(self, x: int, k: int, group):
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
        # Required k managers for the protocol
        deltas = [0] * k
        for i in range(1, k):
            deltas[i] = group.random(ZR)
            deltas[0] -= deltas[i] * (x ** i)
        deltas[0] = group.init(ZR, deltas[0])
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

    def pub_evals_rec(self, id: int, mgr_pk: dict) -> list:
        """
        Publish the delta coefficients

        Parameters
        ----------
        id : int
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
            if i != id:
                pkt = self.encrypt(self.eval_d(i), mgr_pk[i])
            else:
                pkt = 0
            evals[i] = pkt
        return evals

    def comp_shares(self, evals: dict, r_pk: dict, id: int, q) -> list:
        """
        Calculates the shares of the new manager's secret key

        Parameters
        ----------
        evals : dict[list[bytes]]
            Encryption of the delta evaluations published by all managers.
        r_pk : dict
            Public key of the manager being replaced.
        id : int
            Identity of the manager being replaced.
        group : PairingGroup
            Pairing group.

        Returns
        -------
        list[dict]
            Encrypted share of the new manager's secret key.
        """
        x_prime = self.skeg_share
        gamma_prime = self.skbbs_share
        for i in range(1, self.n + 1):
            if i != id:
                dec_delta = self.decrypt(evals[i][self.id])
                x_prime += dec_delta
                gamma_prime += dec_delta
        x_prime = int(x_prime) % q
        gamma_prime = int(gamma_prime) % q
        x_enc = self.encrypt(x_prime, r_pk)
        gamma_enc = self.encrypt(gamma_prime, r_pk)
        return (x_enc, gamma_enc)

    def reconstruct(self, x_shares: list, gamma_shares: list, ss: SecShare, q, k: int):
        x_dec = {}
        gamma_dec = {}
        for i in x_shares.keys():
            x_dec[i] = self.decrypt(x_shares[i])
            gamma_dec[i] = self.decrypt(gamma_shares[i])
        x = ss.reconstruct_d(x_dec, self.id, q, k)
        gamma = ss.reconstruct_d(gamma_dec, self.id, q, k)

        # TODO: Check reconstruction index
        print(f"x_rec      : {x}")
        print(f"gamma_rec  : {gamma}")

        self.skeg_share = x
        self.skbbs_share = gamma

    def gen_epsilon(self, g):
        k = len(self.deltas)
        for m in range(0, k):
            self.epsilons[m] = g ** self.deltas[m]

    def pub_evals_upd(self, mgr_pk: dict) -> dict:
        e = {}
        for i in mgr_pk.keys():
            e[i] = self.encrypt(self.eval_d(i), mgr_pk[i])

        self.time_step += 1
        #TODO: Add signature
        v = {"id": self.id, "time": self.time_step, "epsilons": self.epsilons, "e": e}
        vs = v

        for i in vs["epsilons"].keys():
            vs["epsilons"][i] = str(vs["epsilons"][i])

        for i in vs["e"].keys():
            vs["e"][i] = str(vs["e"][i])
        
        vjson = dumps(vs)
        #TODO: optimize signature
        sigma = "" #self.sign(vjson)

        return (v, sigma)

    def verify_sigs(self, evals: dict, mgr_pk: dict) -> bool:
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
            #TODO: optimize signature
            result = result and True #self.verify(mgr_pk[i], evals[i][0], evals[i][1])

        return result

    def verify_upd(self, evals: dict, g1) -> bool:
        """
        Verifies the correctness of the update packet contents

        Parameters
        ----------
        evals : dict
            Update packets commited by all managers.
        g1 : :py:class:`pairing.Element`
            G1 of the pairing group.

        Returns
        -------
        bool
            True if the contents of the packets are consistent.
        """
        result = True
        for j in evals.keys():
            if j == self.id:
                pkt = evals[j][0]
                u = self.decrypt(pkt["e"][self.id])
                prod = 1
                for m in pkt["epsilons"].keys():
                    prod *= (pkt["epsilons"][m] ** (self.id ** m))
                result = result and (g1 ** u == prod)
        
        return result

    def update_shares(self, evals: dict):
        for j in evals.keys():
            continue
            u = self.decrypt(evals[j][0]["e"][self.id])
            self.skeg_share += u
            self.skbbs_share += u