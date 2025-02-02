from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import ZR
from charm.core.engine.util import objectToBytes
from charm.toolbox.secretshare import *

class BBS():

	def __init__(self, group, g1, g2, h, w, sec_share):
		self.group = group
		self.sec_share = sec_share
		self.u = g1
		self.v = h
		self.g1 = g1
		self.g2 = g2
		self.w = w
		self.h = Hash(pairingElement=self.group)

	def key_issue(self, user, managers: list, mgr_pk: dict):
		com_sh = {}
		for p in managers.values():
			com_sh[p.get_index()] = p.commit_gen(mgr_pk)
		for p in managers.values():
			p.gen_sk(com_sh, mgr_pk)
			p.copy_2_1()
			p.copy_2_4()
			com_sh[p.get_index()] = p.commit_gen(mgr_pk)
		for p in managers.values():
			p.gen_sk(com_sh, mgr_pk)
		mul_sh = {}
		for p in managers.values():
			mul_sh[p.get_index()] = p.mul_shares()
		w_shares = {}
		for p in managers.values():
			ip = self.group.init(ZR, p.get_index())
			w_shares[ip] = p.pool_mul(mul_sh)
		w = managers[1].reconstruct(w_shares)
		for p in managers.values():
			wi = p.reconstruct(w_shares)
			if w != wi:
				raise Exception(f"Response from manager {p.get_index()} doesn't match the first manager")
		winv = w ** -1
		exp_sh = {}
		for p in managers.values():
			p.invert(winv)
			exp_sh[p.get_index()] = p.commit_exp(self.g1)
		for p in managers.values():
			p.verify_exp(exp_sh)
		r = managers[1].pool_exp(exp_sh)
		for p in managers.values():
			ri = p.pool_exp(exp_sh)
			if r != ri:
				raise Exception(f"Response from manager {p.get_index()} doesn't match the first manager")

		pkenc = user.get_pkenc()
		alpha_shares = {}
		for p in managers.values():
			alpha_shares[p.get_index()] = p.get_alpha(pkenc)

		user.set_skU(alpha_shares, mgr_pk)
		user.set_pkU(r)
		user.set_bbs(self)

		return r

	def phi(self, t1, t2, t3, c1, c2):
		tt1 = self.u ** t1
		tt2 = (c1 ** t2) * (self.u ** (-1 * t3))
		tt3 = (self.group.pair_prod(c2, self.g2) ** t2) * (self.group.pair_prod(self.v, self.w) ** (-1 * t1)) * (self.group.pair_prod(self.v, self.g2) ** (-1 * t3))
		return (tt1, tt2, tt3)

	def sign(self, sku, m):
		(r, alpha) = sku
		a = self.group.random(ZR)
		cR = ( self.u ** a, ( self.v ** a ) * r )
		c1, c2 = cR
		r1 = self.group.random(ZR)
		r2 = self.group.random(ZR)
		r3 = self.group.random(ZR)
		calc = self.phi(r1, r2, r3, c1, c2)

		# pasar cosas a bytes antes de hash maybe

		m_bytes = objectToBytes(m, self.group)
		cR_bytes = objectToBytes(cR, self.group)
		calc_bytes = objectToBytes(calc, self.group)
		z = self.h.hashToZr(m_bytes, cR_bytes, calc_bytes)

		t = (z * a, z * alpha, z * a * alpha)
		s = (r1 + t[0], r2 + t[1], r3 + t[2])

		sigma = (z, s)

		return (cR, sigma)

	def verify(self, m, cR, sigma):
		(c1, c2) = cR
		(z, s) = sigma
		(r1, r2, r3) = s

		calc = self.phi(r1, r2, r3, c1, c2)

		t1 = c1 ** z
		t2 = self.group.init(ZR, 1)
		e1 = self.group.pair_prod(self.g1, self.g2)
		e2 = self.group.pair_prod(c2, self.w)
		t3 = (e1 * (e2 ** -1)) ** z

		rp = (calc[0] * (t1 ** -1), calc[1]* (t2 ** -1), calc[2] * (t3 ** -1))

		m_bytes = objectToBytes(m, self.group)
		cR_bytes = objectToBytes(cR, self.group)
		rp_bytes = objectToBytes(rp, self.group)

		hcalc = self.h.hashToZr(m_bytes, cR_bytes, rp_bytes)

		return z == hcalc
