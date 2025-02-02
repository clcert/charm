from charm.core.engine.util import objectToBytes
from charm.toolbox.pairinggroup import G1,ZR,G2
from charm.toolbox.hash_module import *
from tqdm.contrib.concurrent import thread_map
from elgamal import ElGamal
from secshare import SecShare
from util import Server
from bbs import BBS
from ibe import DistIBE
from dimac import Dimac
from wtset import PrivateMultiset
from util import *

class WhoToo():

	def __init__(self, group, k, n, q, mac_k, valid_accusers):
		self.group = group
		self.hashfunc = Hash(pairingElement=self.group)

		self.valid_accusers = valid_accusers
		self.id_map = {}
		self.accusations = []
		self.unique_accs = set()
		self.reused_vals = set()

		self.g1 = self.group.random(G1)
		self.g2 = self.group.random(G2)

		self.k = k
		self.n = n
		self.q = q
		self.mac_k = mac_k

		self.eg = ElGamal(self.group)
		self.sec_share = SecShare(self.group, self.g1, self.g2, self.k, self.n, self.eg)
		self.sec_share.h = self.group.random(G1) # temporal

		# initialize beaver triples
		rbv = self.group.random(ZR)
		a = self.group.random(ZR)
		b = self.group.random(ZR)
		c = a * b
		wa, v = self.sec_share.gen_pedersen(a, rbv)
		wb, v = self.sec_share.gen_pedersen(b, rbv)
		wc, v = self.sec_share.gen_pedersen(c, rbv)

		# initialize servers
		self.servers = []
		for i in range(1, n+1):
			ser = Server(i, n)
			ser.beaver = (wa[i][0], wb[i][0], wc[i][0])
			self.servers += [ser]

		self.sec_share.servers = self.servers

		# initialize ElGamal keys
		h = self.sec_share.geng()
		self.sec_share.h = h
		self.pkeg = {'g': self.g1, 'h': h}
		def temp_func1(p):
			p.skeg_share = p.temp2

		thread_map(temp_func1, self.servers, leave=False)

		# initialize BBS keys
		self.sec_share.gen()
		def temp_func2(p):
			p.temp1 = p.temp2
			p.skbbs_share = p.temp2

		thread_map(temp_func2, self.servers, leave=False)
		self.pkbbs = self.sec_share.exp(self.g2)


		# initialize DIPRF keys
		self.pkdiprf = self.sec_share.geng()
		def temp_func3(p):
			p.skdiprf_share = p.temp2

		thread_map(temp_func3, self.servers, leave=False)


		# initialize IBE key
		self.pkibe = self.sec_share.geng()
		def temp_func4(p):
			p.skibe_share = p.temp2

		thread_map(temp_func4, self.servers, leave=False)

		self.bbs = BBS(self.group, self.g1, self.g2, self.pkeg['h'], self.pkbbs, self.sec_share)
		self.ibe = DistIBE(self.group, self.g1, self.g2, self.pkibe, self.sec_share)
		self.dimac = Dimac(self.sec_share)
		self.mset = PrivateMultiset(self.sec_share, self.eg, self.pkeg)

		self.wtset = self.mset.initialize()

		# initialize user keys and macs
		for u in self.valid_accusers:
			self.servers, r = self.bbs.key_issue(self.servers, u)
			self.id_map[r] = u
			r_bytes = objectToBytes(r, self.group)
			tau = self.hashfunc.hashToZr(r_bytes)
			u.tau = tau

			for i in range(self.mac_k):
				macj = self.dimac.tag(self.servers, tau, u)
				u.macs += [macj]


		# pre-compute random shared values
		def temp_func(p):
			p.gen += [p.temp2]

		num_vals = int(len(valid_accusers)/4)
		for i in range(num_vals):
			self.sec_share.gen(prev=False)
			thread_map(temp_func, self.servers, leave=False)


	def prepare_acc(self, u, d):
		if u.next_mac >= len(u.macs):
				raise Exception('User has used all macs')
		j, dj = u.macs[u.next_mac]
		u.next_mac += 1
		s = self.hashfunc.hashToZr(d.encode('utf-8'))
		w, v, e0, rs = self.sec_share.share_encode(s)
		es = (e0, v[0])
		rd = self.group.random(ZR)
		cD = self.eg.enc_string(self.pkeg, d, rd)
		wt, vt, e0t, rt = self.sec_share.share_encode(u.tau)
		
		for p in self.servers:
			pid = p.id
			mi = (cD, w[pid], v, e0)
			(cR, sigma) = self.bbs.sign((u.R, u.alpha), mi)
			pi0 = self.eg.prove(self.pkeg, es, rs, (cR, sigma))
			pi1 = self.eg.prove(self.pkeg, cD, rd, (cR, sigma))
			p.last_acc = (cR, cD, w[pid], wt[pid], v, vt, e0, e0t, sigma, pi0, pi1, dj, j)

		return cR, cD


	def verify_acc(self):
		def temp_func1(p):
			pid = p.id
			(cR, cD, wi, wti, v, vt, e0, e0t, sigma, pi0, pi1, dj, j) = p.last_acc
			if dj in self.reused_vals: return False

			es = (e0, v[0])
			ver = self.eg.verify(self.pkeg, pi0, es, (cR, sigma))
			if not ver: return False

			ver = self.eg.verify(self.pkeg, pi1, cD, (cR, sigma))
			if not ver: return False

			mi = (cD, wi, v, e0)
			ver = self.bbs.verify(mi, cR, sigma)
			if not ver: return False

			si, ri = wi
			ver = self.sec_share.verify_pedersen(si, ri, v, pid)
			if not ver: return False

			si, ri = wti
			ver = self.sec_share.verify_pedersen(si, ri, vt, pid)
			if not ver: return False

			ver = self.sec_share.verify_pedersen(si, ri, vt, pid)
			if not ver: return False

			p.temp1 = wi[1]
			p.temp2 = wti[1]
			p.temp3 = wi[0] + wti[0]

		thread_map(temp_func1, self.servers, leave=False)

		e0 = self.servers[1].last_acc[6]
		e0t = self.servers[1].last_acc[7]

		ver = self.sec_share.check_consistent(e0)
		if not ver: return False

		def temp_func2(p):
			p.temp1 = p.temp2
		
		thread_map(temp_func2, self.servers, leave=False)

		ver = self.sec_share.check_consistent(e0t)
		if not ver: return False

		def temp_func3(p):
			p.temp1 = p.temp3

		thread_map(temp_func3, self.servers, leave=False)

		prf = self.sec_share.diprf()
		if prf in self.unique_accs: return False
		self.unique_accs.add(prf)

		return True


	def accuse(self, u, d):
		cR, cD = self.prepare_acc(u, d)
		ver = self.verify_acc()

		if not ver:
			raise Exception('Failed to verify accusation')

		def temp_func1(p):
			p.temp1 = p.last_acc[2][0]

		thread_map(temp_func1, self.servers, leave=False)

		self.wtset = self.mset.add(self.servers, self.wtset)
		rhos = self.ibe.enc(self.servers)
		self.accusations.append((cR, rhos, cD))

		def temp_func2(p):
			p.temp1 = p.last_acc[2][0]

		thread_map(temp_func2, self.servers, leave=False)

		quorum = self.mset.quorum(self.servers, self.wtset, self.q)
		if quorum:
			res = self.open_accs()
			d, accs = res
			print('Quorum reached for accused:', str(d))
			print('Accusers:')
			for a in accs:
				print(a.id)
			return res
		else:
			print('Received accusation, quorum has not been reached')
			return None

	
	def open_accs(self):
		accusers = set()
		s_shares = {}
		for p in self.servers:
			dk = self.group.init(ZR, p.id)
			s_shares[dk] = p.last_acc[2][0]

		s = self.sec_share.reconstruct(s_shares)
		d = None
		skid = self.ibe.key_gen(self.servers, s)

		for (cR, rhos, cD) in self.accusations:
			if self.ibe.dec(skid, rhos):
				r = self.sec_share.dist_dec(cR)
				u = self.id_map[r]
				accusers.add(u)
				dp = self.sec_share.dist_dec_str(cD)
				if self.hashfunc.hashToZr(dp) == s:
					d = dp

		if d is None:
			raise Exception('No accusers found')
		
		return (d, accusers)



		
















	


			










