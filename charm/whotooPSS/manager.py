from charm.schemes.pkenc.pkenc_rsa import RSA_Enc
from random import randint

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

    def __init__(self, id: int, n: int, enc: RSA_Enc):
        self.id = id
        self.n = n
        self.da_shares = [0] * n
        self.skeg_share = None
        self.skbbs_share = None
        self.enc = enc
        (self.pkenc, self.skenc) = enc.keygen()
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

    def gen_delta(self, x: int, q: int):
        """
        Computes delta coefficients so the polinomial crosses at x
        
        Parameters
        ----------
        x : int
            Point where the polinomial crosses the x axis.
        """
        # Required k managers for the protocol
        deltas = {1: 0}
        for i in range(2, self.n + 1):
            deltas[i] = randint(1, q-1)
            deltas[1] -= deltas[i] * (x ** i)
        deltas[1] %= q
        self.deltas = deltas

    def pub_deltas(self, id: int, mgr_pk: dict) -> list:
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
        deltas = []
        for i in range(1, self.n + 1):
            if i != id:
                pkt = self.encrypt(self.deltas[i], mgr_pk[i])
            else:
                pkt = 0
            deltas.append(pkt)
        return deltas

    def comp_shares(self, deltas: dict, r_pk: dict, id: int, q: int) -> list:
        """
        Calculates the shares of the new manager's secret key

        Parameters
        ----------
        deltas : dict[list[bytes]]
            Encryption of the delta coeffcients published by all managers.
        id : int
            Identity of the manager beeing replaced.

        Returns
        -------
        list[pairing.Element]
            Share of the new manager's secret key
        """
        x_prime = self.skeg_share
        gamma_prime = self.skbbs_share
        for i in range(1, self.n + 1):
            if i != id:
                dec_delta = self.decrypt(deltas[i][self.id - 1])
                x_prime += dec_delta
                gamma_prime += dec_delta
        x_prime = int(x_prime) % q
        gamma_prime = int(gamma_prime) % q
        x_enc = self.encrypt(x_prime, r_pk)
        gamma_enc = self.encrypt(gamma_prime, r_pk)
        return (x_enc, gamma_enc)

    def reconstruct(self, x_shares: list, gamma_shares: list, ss: SecShare, q: int):
        x_dec = {}
        gamma_dec = {}
        for i in x_shares.keys():
            x_dec[i] = self.decrypt(x_shares[i])
            gamma_dec[i] = self.decrypt(gamma_shares[i])
        x = ss.reconstruct_d(x_dec, self.id, q)
        gamma = ss.reconstruct_d(gamma_dec, self.id, q)

        # TODO: Check reconstruction index
        print(f"x_rec      : {x}")
        print(f"gamma_rec  : {gamma}")
