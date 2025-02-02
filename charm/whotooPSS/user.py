from charm.toolbox.pairinggroup import ZR
from nacl.public import (
    Box,
    PrivateKey,
    PublicKey
)
from nacl.utils import EncryptedMessage

from bbs import BBS
from secshare import SecShare
from util import base64_to_bytes

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
    n : int
        Number of managers in the scheme.
    sec_share : :py:class:`secshare.SecShare`
        Secret share scheme.
    bbs : :py:class:`bbs.BBS`
        BBS scheme.
    skenc : :py:class:`nacl.public.PrivateKey`
        Secret key for encryption scheme.
    R : :py:class:`pairing.Element`
        Public key.
    alpha : :py:class:`pairing.Element`
        Secret key.
    """

    def __init__(self, id, n):
        self.id = id
        self.n = n
        self.sec_share = None
        self.bbs = None

        self.skenc = PrivateKey.generate()
        self.R = None
        self.alpha = None

    def set_nacl(self, skenc: str):
        """
        Sets the encryption key from a base64 string.

        Parameters
        ----------
        skenc : str
            Encryption secret key.
        """
        self.skenc = PrivateKey(base64_to_bytes(skenc))

    def init_schemes(self, group, g1, g2, k, pkeg, pkbbs):
        """
        Initializes the secret share scheme.
        """
        self.sec_share = SecShare(group, g1, g2, k, self.n)
        self.sec_share.h = pkeg["h"]
        self.bbs = BBS(group, g1, g2, pkeg["h"], pkbbs, self.sec_share)

    def get_pkenc(self) -> PublicKey:
        """
        Gets the user's encryption public key

        Returns
        -------
        :py:class:`nacl.public.PublicKey`
            Manager's public key
        """
        return self.skenc.public_key

    def _get_skenc(self) -> bytes:
        """
        Gets the user's encryption secret key

        Returns
        -------
        bytes
            Manager's public key
        """
        return self.skenc.encode()

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

    def set_bbs(self, bbs):
        """
        Sets the BBS scheme
        """
        self.bbs = bbs

    def sign(self, msg: str) -> tuple:
        """
        Signs a message

        Parameters
        ----------
        msg : str
            Message to be signed.

        Returns
        -------
        tuple
            BBS signature.
        """
        return self.bbs.sign((self.R, self.alpha), msg)