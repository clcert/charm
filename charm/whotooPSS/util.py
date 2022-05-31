from base64 import b64decode
from charm.core.engine.util import objectToBytes
from charm.toolbox.pairinggroup import ZR
from charm.toolbox.hash_module import Hash

def base64_to_bytes(key: str) -> bytes:
	"""
	Creates a byte array from base64 encoded key.

	Parameters
	----------
	key : str
		key encoded in base64.
	
	Returns
	-------
	bytes
		Byte array to reconstruct the key.
	"""
	return b64decode(key.encode("utf-8"))

def pedersen_commit(g, h, msg, r):
	return (g ** msg) * (h ** r)

def zklogeq(group, g, h, x):
	r = group.random(ZR)
	a1 = g ** r
	a2 = h ** r
	a = (a1, a2)
	gx = g ** x

	a1_bytes = objectToBytes(a1, group)
	a2_bytes = objectToBytes(a2, group)
	g_bytes = objectToBytes(g, group)
	gx_bytes = objectToBytes(gx, group)


	h = Hash(pairingElement=group)
	c = h.hashToZr(g_bytes, gx_bytes, a1_bytes, a2_bytes)

	t = r + c*x

	return a, c, t

def zklogeq_verify(g, h, gx, hx, a, c, t):
	a1, a2 = a
	v1 = (g ** t == a1 * (gx ** c))
	v2 = (h ** t == a2 * (hx ** c))
	return (v1 and v2)