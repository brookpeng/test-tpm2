import asyncio
import ssl
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner


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


if __name__ == '__main__':

    ssl.match_hostname = lambda cert, hostname: True
    ca_cert_path = '../client-cert/ca-cert.pem'
    print(ca_cert_path)
    client_cert_path = '../client-cert/client-cert.pem'
    print(client_cert_path)
    client_key_path = '../client-cert/client-priv.pem'
    print(client_key_path)

    # context = ssl.create_default_context(capath='../client-cert/')
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_REQUIRED
    # load a set of CA files
    context.load_verify_locations(ca_cert_path)
    # load a client's cert and private key
    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)

    # url = "ws://127.0.0.1:8080/ws"
    url = "wss://127.0.0.1:9000"
    realm = "crossbardemo"
    runner = ApplicationRunner(url, realm, ssl=context)
    runner.run(Component)