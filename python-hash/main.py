import sys
import os.path
import hashlib
import ctypes
_libcrypto = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libcrypto.so")
_libssl = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libssl.so")
BLOCKSIZE = 65536
kEY_HANDLE = b"/home/daniel/Documents/build-tpm2/simple-tpm-mutual-tls/python-hash/home-priv.tss"

# class _StrBuffer(object):
# 	__slots__ = ('str', '_as_parameter_')
# 	def __init__(self, str):
# 		self.str = str
# 		self._as_parameter_ = ctypes.pythonapi.(id(self.str))

# def malloc(data, size):
# 	buffer = None
# 	if data != 0:
# 		if sys.version_info.major == 3 and isinstance(data, type('')):
# 			data = data.encode()
# 			buffer = ctypes.create_string_buffer(data, size)
# 		else:
# 			buffer = ctypes.create_string_buffer(size)
# 	return buffer

def _init():

	_libssl.OPENSSL_init_ssl.argtypes = [ctypes.c_longlong, ctypes.c_void_p]
	_libssl.OPENSSL_init_ssl.restype = ctypes.c_int

	_libcrypto.ENGINE_load_private_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
	_libcrypto.ENGINE_load_private_key.restype = ctypes.c_void_p

	_libcrypto.EVP_PKEY_get1_RSA.argtypes = [ctypes.c_void_p]
	_libcrypto.EVP_PKEY_get1_RSA.restype = ctypes.c_void_p

	# _libcrypto.EVP_MD_CTX_create.argtypes = []
	# _libcrypto.EVP_MD_CTX_create.restype = ctypes.c_void_p

	# _libcrypto.EVP_MD_CTX_init.argtypes = [ctypes.c_void_p]
	# _libcrypto.EVP_MD_CTX_init.restype = None

	_libcrypto.EVP_sha1.argtypes = []
	_libcrypto.EVP_sha1.restype = ctypes.c_void_p

	_libcrypto.EVP_sha256.argtypes = []
	_libcrypto.EVP_sha256.restype = ctypes.c_void_p

	_libcrypto.EVP_sha512.argtypes = []
	_libcrypto.EVP_sha512.restype = ctypes.c_void_p

	_libcrypto.ENGINE_set_default_RSA.argtypes = [ctypes.c_void_p]
	_libcrypto.ENGINE_set_default_RSA.restype = ctypes.c_int

	_libcrypto.EVP_PKEY_set1_RSA.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
	_libcrypto.EVP_PKEY_set1_RSA.restype = ctypes.c_int

	_libcrypto.EVP_DigestInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
	_libcrypto.EVP_DigestInit.restype = ctypes.c_int

	_libcrypto.EVP_DigestUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
	_libcrypto.EVP_DigestUpdate.restype = ctypes.c_int

	_libcrypto.EVP_DigestFinal.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_uint)]
	_libcrypto.EVP_DigestFinal.restype = ctypes.c_int

	_libcrypto.EVP_SignFinal.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p]
	_libcrypto.EVP_SignFinal.restype = ctypes.c_int

	_libcrypto.EVP_PKEY_size.argtypes = [ctypes.c_void_p]
	_libcrypto.EVP_PKEY_size.restype = ctypes.c_int

	_libcrypto.EVP_EncodeBlock.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
	_libcrypto.EVP_EncodeBlock.restype = ctypes.c_int

def init_ssl_engine(engine):
	_libcrypto.ENGINE_load_builtin_engines()
	e = _libcrypto.ENGINE_by_id(engine)
	if e == None:
		raise ValueError('Cannot find engine {}'.format(engine))

	if not _libcrypto.ENGINE_init(e):
		_libcrypto.ENGINE_free(e)
		raise Exception('Cannot initialize engine {}'.format(engine))
	print('Engine {} is ready to use: {}'.format(engine, e))

	if not _libcrypto.ENGINE_set_default_RSA(e):
		_libcrypto.ENGINE_free(e)
		raise ValueError('Cannot set engine as default for RSA {}'.format(e))

	key = _libcrypto.ENGINE_load_private_key(e, kEY_HANDLE, None, None)
	rsa = _libcrypto.EVP_PKEY_get1_RSA(key)
	_libcrypto.EVP_PKEY_free(key)

	return rsa

def rsa_sign_with_key(rsa, filename):

	with open(filename, 'rb') as f:
		data = f.read()
		type(data)

		data_ptr = ctypes.c_char_p(data)
		data_void_ptr = ctypes.cast(data_ptr, ctypes.c_void_p)

		key = _libcrypto.EVP_PKEY_new()
		ret = _libcrypto.EVP_PKEY_set1_RSA(key, rsa)
		if ret != 1:
			print('error EVP_PKEY_set1_RSA()')

		keysize = _libcrypto.EVP_PKEY_size(key)

		outbuf = (ctypes.c_ubyte * keysize)()
		# outbuf_addr = ctypes.addressof(outbuf)
		# outptr = ctypes.cast(outbuf_addr, ctypes.c_void_p)
		# output = ctypes.create_string_buffer(str.encode(outbuf))

		lenbuf = ctypes.c_uint()
		lenbuf_addr = ctypes.addressof(lenbuf) 
		lenptr = ctypes.cast(lenbuf_addr, ctypes.POINTER(ctypes.c_uint))

		# context = _libcrypto.EVP_MD_CTX_create()
		context = _libcrypto.EVP_MD_CTX_new()
		# _libcrypto.EVP_MD_CTX_init(context)
		ret = _libcrypto.EVP_DigestInit(context, _libcrypto.EVP_sha256())
		if ret != 1:
			print('error EVP_DigestInit()')

		ret = _libcrypto.EVP_DigestUpdate(context, data, len(data))
		if ret != 1:
			print('error EVP_DigestUpdate()')
		ret = _libcrypto.EVP_SignFinal(context, outbuf, lenptr, key)
		if ret != 1:
			print('error EVP_SignFinal()')

	base64 = (ctypes.c_ubyte * 4096)()
	base64_len = _libcrypto.EVP_EncodeBlock(base64, outbuf, lenptr[0])

	# outstring = ctypes.cast(outbuf, ctypes.c_char_p)
	# print(outstring.value)
	# print(lenptr[0])

	# print(base64_len)
	print(ctypes.string_at(base64, base64_len))
	return base64

def sign_hash(filename):
	_init()
	_libssl.OPENSSL_init_ssl(0, None)
	# _libssl.SSL_library_init()
	# _libssl.SSL_load_error_strings()
	# _libcrypto.OPENSSL_add_all_algorithms_conf()
	# _libcrypto.OpenSSL_add_all_digests()
	# _libcrypto.OpenSSL_add_all_ciphers()

	rsa = init_ssl_engine(b"tpm2tss")
	output = rsa_sign_with_key(rsa, filename)


def get_hash(file):
	hasher = hashlib.sha1()
	with open(file, 'rb') as f:
		buf = f.read(BLOCKSIZE)
		while len(buf) > 0:
			hasher.update(buf)
			buf = f.read(BLOCKSIZE)
	return hasher.hexdigest()


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: %s [FILE_PATH]" % sys.argv[0])
		sys.exit(1)
	# file_hash = get_hash(sys.argv[1])
	# print(file_hash)
	if not os.path.isfile(sys.argv[1]):
		print("The file, %s is invalid" % sys.argv[1])
		sys.exit(1)
	sign_hash(sys.argv[1])