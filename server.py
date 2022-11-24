import asyncio
import tinyec
from aioconsole import ainput
import sys

import commonFunctions as cf
import EccRsa as c


class Server:
    def __init__(self, ip: str, port: int, loop: asyncio.AbstractEventLoop, privKey: int, pubKey: tinyec.ec.Point, Curve: tinyec.ec.Curve):
        '''
        Parameters
        ----------
        ip : str
            IP that the server will be using
        port : int
            Port that the server will be using
        ----------
        '''
        self.__ip: str = ip
        self.__port: int = port
        self.__loop: asyncio.AbstractEventLoop = loop
        self.__conn: bool = False
        self.__server_on: bool = True
        self.__privKey: int = privKey
        self.__pubKey: tinyec.ec.Point = pubKey
        self.__Curve: tinyec.ec.Curve = Curve
        self.__pubKey_client: tinyec.ec.Point = None
 
        print(f"Server ready on {self.ip}:{self.port}")
        print(f"Useful command: \private_key, \public_key, \quit")

    @property
    def ip(self):
        return self.__ip

    @property
    def port(self):
        return self.__port
 
    @property
    def loop(self):
        return self.__loop

    @property
    def conn(self):
        return self.__conn

    @property
    def server_on(self):
        return self.__server_on

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
    def pubKey_client(self):
        return self.__pubKey_client

    def set_pubKey_client(self, value: tinyec.ec.Point):
        self.__pubKey_client = value

    def set_conn_flag(self, value: bool):
        self.__conn = value
    
    def state_server(self, value: bool):
        self.__server_on = value

    async def accept_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        ''' 
        Function to handle the new connection, starting the task to read and write with client
        '''
        try: 
            if self.conn == False:
                # PubKey and Private Key exchange
                keyExchange = asyncio.create_task(self.exchange_key(client_reader, client_writer))
                await keyExchange

                # Starting two task, the first one await to read the stream of the client and the second one await response of the server
                asyncio.gather(
                    self.handle_client(client_reader, client_writer), 
                    self.server_response(client_writer),
                    self.check_connection()
                )
                
                # Print some information about the client
                client_ip = client_writer.get_extra_info('peername')[0]
                client_port = client_writer.get_extra_info('peername')[1]
                print(f"New Connection: {client_ip}:{client_port}")

                self.set_conn_flag(True)
            else:
                print("Server full")
        except Exception as e:
            print(e)

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
            
            if self.server_on == False:
                self.shutdown_server()
                break

            await asyncio.sleep(1)

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        ''' 
        Function to read and interact with client messages 
        '''
         
        # loop to continue read the stream of the client
        while True:
            # await messages from client
            raw_client_message = await client_reader.read(255)
            client_message = cf.decrypt_messages(Curve= self.Curve, privKey= self.privKey, dataRec=raw_client_message.decode('utf-8').split(delimit))
            
            # custom behaviour of the server when received a trigger message
            if client_message.startswith("\n"):
                continue

            if client_message.startswith("\quit"):
                raw_data = "\quit"
                encrypted_message = cf.encrypt_messages(pubKey= self.pubKey_client, Curve= self.Curve, plain_text=raw_data.encode('utf8'))
                client_writer.write(encrypted_message)           
                await client_writer.drain()    
                print("Client Disconnected")
                self.set_conn_flag(False)
                break        
            
            print(f"{client_writer.get_extra_info('peername')[0]}: {client_message}")

    async def exchange_key(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        ''' 
        Function to exchange PubKey and PrivKey 
        '''

        dataRec = ''
        while True:
            dataRec = str((await client_reader.read(255)).decode())
            if dataRec != '':
                key = cf.pubKeyReconstruction(dataRec, curve)
                self.set_pubKey_client(key)
                break
            
        data = str(str(self.pubKey.x) + delimit + str(self.pubKey.y))
        client_writer.write(data.encode())

    async def server_response(self, client_writer: asyncio.StreamWriter):
        ''' 
        Function to send messages to the client 
        '''
        asyncio.current_task().set_name("task-sending")

        server_message: str = None

        while True:
            # await input from terminal
            server_message = await ainput("")

            # custom behaviour of the server when the user put a trigger input 
            if server_message == "\public_key":
                print(f"pubKey: {c.compress_point(self.pubKey)} \nclient: {c.compress_point(self.pubKey_client)}")
                continue

            if server_message == "\private_key":
                print(f"Private key: {self.privKey}")
                continue

            if server_message == "\quit":
                encrypted_message = cf.encrypt_messages(pubKey= self.pubKey_client, Curve= self.Curve, plain_text=server_message.encode('utf8'))
                client_writer.write(encrypted_message)           
                await client_writer.drain()
                self.state_server(False)    
                break

            if server_message != "":
                encrypted_message = cf.encrypt_messages(pubKey= self.pubKey_client, Curve= self.Curve, plain_text=server_message.encode('utf8'))
                client_writer.write(encrypted_message)           
                await client_writer.drain()         

    def start_server(self):
        '''
        Starts the server on the IP and PORT.
        '''
        try:
            self.server = asyncio.start_server(
                self.accept_client, self.ip, self.port
            )
            self.loop.run_until_complete(self.server)
            self.loop.run_forever()
        except Exception as e:
            print(e)
            self.shutdown_server()
        except KeyboardInterrupt:
            self.shutdown_server()

    def shutdown_server(self):
        print("Shutting down server!")
        self.loop.stop()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} HOST_IP PORT")

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
curve, privkey, pubkey = c.keysCreation()
delimit = '\0'

server = Server(sys.argv[1], sys.argv[2], loop, privKey = privkey, pubKey= pubkey, Curve=curve)

server.start_server()

