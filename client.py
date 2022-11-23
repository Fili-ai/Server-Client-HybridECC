import asyncio
from aioconsole import ainput
import tinyec
import sys

import commonFunctions as cf
import EccRsa as c

class Client:
    def __init__(self, server_ip: str, server_port: int, loop: asyncio.AbstractEventLoop, privKey: int, pubKey: tinyec.ec.Point, Curve: tinyec.ec.Curve):
        self.__server_ip: str = server_ip
        self.__server_port: int = server_port
        self.__conn: bool = False
        self.__loop: asyncio.AbstractEventLoop = loop
        self.__privKey: int = privKey
        self.__pubKey: tinyec.ec.Point = pubKey
        self.__Curve: tinyec.ec.Curve = Curve
        self.__pubKey_server: tinyec.ec.Point = None
        self.__reader: asyncio.StreamReader = None
        self.__writer: asyncio.StreamWriter = None


    @property
    def server_ip(self):
        return self.__server_ip

    @property
    def server_port(self):
        return self.__server_port
    
    @property
    def conn(self):
        return self.__conn

    @property
    def loop(self):
        return self.__loop

    @property
    def privKey(self):
        return self.__privKey

    @property
    def pubKey(self):
        return self.__pubKey
    
    @property
    def Curve(self):
        return self.__Curve
    
    @property
    def pubKey_server(self):
        return self.__pubKey_server

    @property
    def reader(self):
        return self.__reader

    @property
    def writer(self):
        return self.__writer
    
    def set_puKey_server(self, value: tinyec.ec.Point):
        self.__pubKey_server = value

    def set_conn_flag(self, value):
        self.__conn = value

    async def connect_to_server(self):
        '''
        Function to connecct to the server. This function will also set the reader/writer properties
        upon successful connection to server.
        '''
        try:
            # open the connection with the server
            self.__reader, self.__writer = await asyncio.open_connection(
                self.server_ip, self.server_port)

            # exchange privKey and Pubkey
            keyExchange = asyncio.create_task(self.exchange_key())
            await keyExchange
            
            self.set_conn_flag(True)

            print("Client ready to chat! Useful command: \private_key, \public_key, \quit")

            # start the task to receive and write to the server
            await asyncio.gather(
                self.receive_messages(),
                self.start_client_cli(),
                self.check_connection(),
                return_exceptions=True
            )

        except Exception as e:
            print(e)
            pass
        except KeyboardInterrupt:
            print("Interrupted by keyboard")

        print("Shutting down")
    
    async def check_connection(self):
        '''
        Function to stop the writing task when the server quit
        '''
        asyncio.current_task().set_name("task-check")

        while True:
            if self.conn == False:
                for task in asyncio.all_tasks():
                    if task.get_name() == "task-sending":
                        task.cancel()

                self.close_connection()
                break
            else:
                await asyncio.sleep(1)

    async def exchange_key(self):
        '''
        Function to exchange the PubKey and the private Key
        '''       
        data = str(str(self.pubKey.x) + delimit + str(self.pubKey.y))
        self.writer.write(data.encode())

        dataRec = str((await self.reader.read(255)).decode())
        value = cf.pubKeyReconstruction(dataRec, curve)
        self.set_puKey_server(value)

    async def receive_messages(self):
        '''
        Function to receive the message from the server
        '''     

        asyncio.current_task().set_name("task-receiving")

        server_message: str = None
        while self.conn:
            raw_server_message = await self.reader.read(255)
            server_message = cf.decrypt_messages(self.Curve, self.privKey, raw_server_message.decode('UTF-8').split(delimit))
            
            if server_message.startswith("\n"):
                continue

            if server_message.startswith("\quit"):
                print("Server-side connection close")
                self.set_conn_flag(False)
                break

            print(f"{self.server_ip}: {server_message}")
        

    async def start_client_cli(self):
        '''
        Function to write messages to the server
        '''
        asyncio.current_task().set_name("task-sending")
        client_message: str = None

        while self.conn:
            client_message = await ainput("")

            if client_message.startswith("\private_key"):
                print(f"private key: {self.privKey}")
                continue

            if client_message.startswith("\public_key"):
                print(f"pubKey: {c.compress_point(self.pubKey)} \nclient: {c.compress_point(self.pubKey_server)}")
                continue

            if client_message.startswith("\quit"):
                encrypted_message = cf.encrypt_messages(pubKey= self.pubKey_server, Curve= self.Curve, plain_text= client_message.encode('utf8'))
                self.writer.write(encrypted_message)
                await self.writer.drain()
                self.set_conn_flag(False)
                break

            if client_message != "":
                encrypted_message = cf.encrypt_messages(pubKey= self.pubKey_server, Curve= self.Curve, plain_text= client_message.encode('utf8'))
                self.writer.write(encrypted_message)
                await self.writer.drain()

    def close_connection(self):
        print("Connection Closed")
        self.loop.stop()

'''
if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} SERVER_IP PORT")
'''

curve, privkey, pubkey = c.keysCreation()
delimit = '\0'

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
#client = Client("192.168.1.11", 4646, loop, privKey = privkey, pubKey = pubkey, Curve = curve)
client = Client("127.0.0.1", 4646, loop, privKey = privkey, pubKey = pubkey, Curve = curve)

asyncio.run(client.connect_to_server())
