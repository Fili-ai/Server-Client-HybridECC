# Server-Client-HybridECC

## Goal

Server and client that can communicate using:

- ECC cryptography;
- ECDH key exchange;
- symmetric encryption algorithm.

## Resources

In this section I'm going to mention the main sources on which my work is based:

- Encryption/decryption/ECC
  - <https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/asymmetric-key-ciphers/ecc-encryption-decryption.md>;
  - <https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc.html>;
- Asyncio
  - <https://testingonprod.com/2021/10/10/asynchronous-server-client-with-python-0x01-starting-our-server/>
  - <https://realpython.com/async-io-python/>

## Installation

Firstly, clone the repository:

```Bash
git clone https://github.com/Fili-ai/Server-Client-HybridECC.git   
```

Fix all the necessary libraries:

```Bash
pip install -r requirements.txt
```

## How to use

After activating venv you can:

- Running the server:

```Python
python3 server.py [Host IP] [PORT]
```

- Running the client:

```Python
python3 client.py [Server IP] [PORT]
```
