import EccRsa as c
import tinyec
import binascii

delimit = '\0'

def pubKeyReconstruction(data: str, curve: tinyec.ec.Curve) -> tinyec.ec.Point:
    
    datas = data.split(delimit)
    x = int(datas[0])
    y = int(datas[1])

    pubKey = tinyec.ec.Point(curve, x, y)

    return pubKey


def encrypt_messages(pubKey: tinyec.ec.Point, Curve: tinyec.ec.Curve, plain_text: bytes) -> bytes:
    ''' 
    Function to encrypt messages
    '''  

    try:
        encrypted_data = c.encrypt_ECC(plain_text, pubKey, Curve)
        data = str(encrypted_data[3].x) + delimit + str(encrypted_data[3].y)
        HexMsg = encrypted_data[0].hex() + delimit + encrypted_data[1].hex() + delimit + encrypted_data[2].hex() + delimit + data
    except Exception as e:
        print(f"Error during encripting: {e}")
    
    return bytes(HexMsg, 'UTF-8')

def decrypt_messages(Curve: tinyec.ec.Curve, privKey: int, dataRec: list) -> str:
    ''' 
    Function to decrypt messages
    '''     

    encryptedMsg = [0, 0, 0, 0]
    try:
        encryptedMsg[0] = binascii.unhexlify(dataRec[0])
        encryptedMsg[1] = binascii.unhexlify(dataRec[1])
        encryptedMsg[2] = binascii.unhexlify(dataRec[2])
        encryptedMsg[3] = tinyec.ec.Point(Curve, int(dataRec[3]), int(dataRec[4]))

        plaintext = c.decrypt_ECC(encryptedMsg, privKey)
        return plaintext.decode('UTF-8')
    except Exception as e:
        print(f"Error during decrypting: {e}")
        print(f"DataRec: {dataRec}")
        return("Failed to decrypt")