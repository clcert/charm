from pydoc import doc
from quopri import encode
from charm.schemes.pkenc.pkenc_rsa import RSA_Enc
from random import randint

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
    deltas : list[int]
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
        deltas = [0]
        for i in range(1, self.n):
            deltas.append(randint(1, q) % q)
            deltas[0] -= deltas[i] * (x ** i)
        deltas[0] %= q
        self.deltas = deltas

    def pub_deltas(self, id: int, mgr_pk: list) -> list:
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
                pkt = self.encrypt(self.deltas[i-1], mgr_pk[i-1])
            else:
                pkt = 0
            deltas.append(pkt)
        return deltas

    def comp_shares(self, deltas: dict, id: int) -> list:
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
        return (x_prime, gamma_prime)