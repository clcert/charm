from charm.schemes.pkenc.pkenc_cs98 import CS98

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
    """

    def __init__(self, id: int, n: int, cs: CS98):
        self.id = id
        self.da_shares = [0] * n
        self.skeg_share = None
        self.skbbs_share = None
        self.enc = cs
        (self.pkenc, self.skenc) = cs.keygen()
        self.temp1 = None
        self.temp2 = None
        self.temp3 = None
        self.temp4 = None
        self.temp5 = None
        self.temp6 = None
        self.temp7 = None
        self.beaver = None
        self.gen = []
        self.delta = []

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
        m = msg.to_bytes(20, byteorder='big')
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
        return int.from_bytes(rm, byteorder='big')

    def gen_delta(self):
        pass

    def pub_delta(self, id: int):
        pass

    def comp_shares(self, deltas, id: int):
        pass