import asyncio
import ssl
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner


class Component(ApplicationSession):
    """
    An application component that subscribes and receives events, and
    stop after having received 5 events.
    """

    async def onJoin(self, details):

        self.received = 0

        def on_event(i):
            print("Got event: {}".format(i))
            self.received += 1
            if self.received > 5:
                self.leave()

        await self.subscribe(on_event, 'com.myapp.topic')

    def onDisconnect(self):
        asyncio.get_event_loop().stop()


if __name__ == '__main__':

    ssl.match_hostname = lambda cert, hostname: True
    ca_cert_path = '../client-cert/ca-cert.pem'
    print(ca_cert_path)
    client_cert_path = '../client-cert/client-cert.pem'
    print(client_cert_path)
    client_key_path = '../client-cert/client-priv.pem'
    print(client_key_path)

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

