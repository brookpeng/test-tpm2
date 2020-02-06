import asyncio
import ssl
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner

import ctypes
_libcrypto = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libcrypto.so")
_libssl = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libssl.so")

class Component(ApplicationSession):
    """
    An application component that publishes an event every second.
    """

    async def onJoin(self, details):
        counter = 0
        while True:
            print("publish: com.myapp.topic", counter)
            self.publish('com.myapp.topic', counter)
            counter += 1
            await asyncio.sleep(1)

def init_ssl_engine(engine, context):

    _libcrypto.ENGINE_load_builtin_engines()
    e = _libcrypto.ENGINE_by_id(engine)
    if e == None:
        raise ValueError('Cannot find engine {}'.format(engine))

    if not _libcrypto.ENGINE_init(e):
        _libcrypto.ENGINE_free(e)
        raise Exception('Cannot initialize engine {}'.format(engine))
    print('Engine {} is ready to use: {}'.format(engine, e))

    # u = _lib.UI_OpenSSL()
    key = _libcrypto.ENGINE_load_private_key(e, b"/home/dwang3/Desktop/tls-tpm/tpm-gen-cert/tpm-client-priv.tss", None, None)

    ctx = ctypes.cast(id(context) + ctypes.sizeof(ctypes.c_void_p) * 2, ctypes.POINTER(ctypes.c_void_p)).contents

    print(_libssl.SSL_CTX_use_PrivateKey(ctx, key))
    # print(_libssl.SSL_CTX_use_certificate_file(ctx, b"/home/dwang3/Desktop/tls-tpm/tpm-gen-cert/tpm-client-cert.pem", 1))
    print(_libssl.SSL_CTX_use_certificate_chain_file(ctx, b"/home/dwang3/Desktop/tls-tpm/tpm-gen-cert/tpm-client-cert-chain.pem"))
    return e

def free_engine(e):
    print("stop openssl engine")
    _libcrypto.ENGINE_finish(e)
    _libcrypto.ENGINE_free(e)


if __name__ == '__main__':
    # ssl.match_hostname = lambda cert, hostname: True
    ca_cert_path = '../client-cert/ca-cert.pem'
    print(ca_cert_path)
    # client_cert_path = '../client-cert/client-cert.pem'
    # print(client_cert_path)
    # client_key_path = '../client-cert/client-priv.pem'
    # print(client_key_path)

    # context = ssl.create_default_context(capath='../client-cert/')
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_REQUIRED
    # load a set of CA files
    # context.load_verify_locations(ca_cert_path)
    # load a client's cert and private key
    # context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)

    # start engine and load tpm2tss private key
    e = init_ssl_engine(b'tpm2tss', context)

    # url = "ws://127.0.0.1:8080/ws"
    url = "wss://127.0.0.1:9000"
    realm = "crossbardemo"
    runner = ApplicationRunner(url, realm, ssl=context)
    runner.run(Component)

    free_engine(e)