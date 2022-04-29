from charm.toolbox.pairinggroup import ZR
from nacl.public import (
    Box,
    PrivateKey,
    PublicKey
)
from nacl.utils import EncryptedMessage

from secshare import SecShare

class User():
    """
    User class

    skU = (A, alpha)
        A : R
        alpha : alpha

    Attributes
    ----------
    id : int
        Identifier of the user.
    da_shares : list[:py:class:`pairing.Element`]
        Shares of distributed authority commitment.
    R : :py:class:`pairing.Element`
        Public key.
    alpha : :py:class:`pairing.Element`
        Secret key.
    """
    def __init__(self, id, n, ss: SecShare):
        self.id = id
        self.n = n
        self.sec_share = ss
        self.skenc = PrivateKey.generate()
        self.R = None
        self.alpha = None
        self.temp = None

    def get_pkenc(self) -> PublicKey:
        """
        Gets the user's encryption public key

        Returns
        -------
        :py:class:`nacl.public.PublicKey`
            Manager's public key
        """
        return self.skenc.public_key

    def decrypt(self, cph: EncryptedMessage, spk: PublicKey) -> str:
        """
        Decrypts a message intended to the user

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

    def reconstruct(self, shares: dict):
        """"""
        return self.sec_share.reconstruct(shares)

    def set_pkU(self, R):
        """
        Sets the public signing key

        Parameters
        ----------
        R : :py:class:`pairing.Element`
            New public key.
        """
        self.R = R

    def set_skU(self, shares, mgr_pk):
        """
        Computes the secret signing key

        Parameters
        ----------
        shares : dict
            Encrypted shares of the secret key.
        mgr_pk : dict
            Public encryption keys of the managers.
        """
        dec_shares = {}
        for i in range(1, self.n + 1):
            ip = self.sec_share.group.init(ZR, i)
            dec = int(self.decrypt(shares[i], mgr_pk[i]))
            dec_shares[ip] = self.sec_share.group.init(ZR, dec)
        self.alpha = self.reconstruct(dec_shares)