from charm.toolbox.pairinggroup import ZR
from charm.toolbox.secretshare import SecretShare

from util import pedersen_commit

class SecShare():

	def __init__(self, group, g1, g2, k, n):
		self.group = group
		self.g1 = g1
		self.g2 = g2
		self.k = k
		self.n = n
		self.h = None
		self.ss = SecretShare(self.group, verbose_status=False)
		shares = {self.group.init(ZR, i):0 for i in range(1, self.n + 1)}
		self.coeffs = self.ss.recoverCoefficients(shares)

	def gen_pedersen(self, s, r, feldman=False):
		s_shares, s_coeffs = self.ss.genShares(s, k=self.k, n=self.n)
		r_shares, r_coeffs = self.ss.genShares(r, k=self.k, n=self.n)

		w = list(zip(s_shares, r_shares))
		v = []

		if feldman:
			v_feldman =[]

		for i in range(len(s_coeffs)):
			vi = pedersen_commit(self.g1, self.h, s_coeffs[i], r_coeffs[i])
			v += [vi]

			if feldman:
				vif = self.g1 ** s_coeffs[i]
				v_feldman += [vif]

		if feldman:
			return w, v, v_feldman

		return w, v

	def verify_pedersen(self, si, ri, v, i):
		expected = (self.g1 ** si) * (self.h ** ri)
		verification = v[0]
		for j in range(1, len(v)):
			verification *= ( v[j] ** (i ** j) )

		return expected == verification

	def verify_feldman(self, si, v, i):
		expected = self.g1 ** si
		verification = v[0]

		for j in range(1, len(v)):
			verification *= v[j] ** (i ** j)

		return expected == verification

	def reconstruct(self, shares):
		return self.ss.recoverSecret(shares)

	def reconstruct_d(self, shares: dict, x: int, k: int):
		"""
		Reconstruct a share at a given index

		Parameters
		----------
		shares : dict[:py:class:`pairing.Element` -> :py:class:`pairing.Element`]
			Known shares of the polynomial.
		x : int
			Desired index for reconstruction.
		k : int
			Degree of the polynomial.

		Returns
		-------
		:py:class:`pairing.Element`
			Reconstructed value of P(x).
		"""
		lst = shares.keys()
		lst = list(lst)[:k+1]
		coeff = self.recover_coeff(lst, x)
		secret = 0
		for i in lst:
			secret += coeff[i] * shares[i]
		return secret

	def recover_coeff(self, lst: list, x: int) -> dict:
		"""
		Computes the coefficients for Lagrange interpolation
		
		Parameters
		----------
		lst : list[:py:class:`pairing.Element`]
			Indeces where the value of the polynomial is known.
		x : int
			Desired interpolation index.

		Returns
		-------
		dict : dict[:py:class:`pairing.Element` -> :py:class:`pairing.Element`]
			Coefficients corresponding to each known value of the polynomial.
		"""
		coeff = {}
		for i in lst:
			result = 1
			for j in lst:
				if not (i == j):
					# lagrange basis poly
					result *= (x - j) / (i - j)
			coeff[i] = result
		return coeff