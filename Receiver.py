import base64
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.consts import Mode
import json


def bytes_to_base64(byte_data):
    return base64.b64encode(byte_data).decode('utf-8')


def base64_to_bytes(base64_string):
    return base64.b64decode(base64_string.encode('utf-8'))


def decription(path):
    # Read from the JSON file
    with open(path, 'r') as file:
        data = json.load(file)

    # Access the values
    psk = base64_to_bytes(data['info']['psk'])
    psk_id = base64_to_bytes(data['info']['psk_id'])
    # sk = None if data['info']['sk'] == "None" else base64_to_bytes(data['info']['sk'])
    info = base64_to_bytes(data['pub_data']['info'])
    aad = base64_to_bytes(data['pub_data']['aad'])
    ikm_s = None if data['pub_data']['ikm_s'] is None else base64_to_bytes(data['pub_data']['ikm_s'])
    ikm_r = base64_to_bytes(data['pub_data']['ikm_r'])
    enc = base64_to_bytes(data['pub_data']['enc'])
    ct = base64_to_bytes(data['pub_data']['ct'])
    # The recipient side:
    suite_r = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
    )
    pks = None
    if ikm_s is not None:
        pks = suite_r.kem.derive_key_pair(ikm_s).public_key  # serve per il pks per AUTH
    skr = suite_r.kem.derive_key_pair(ikm_r).private_key  # chiave privata receiver
    recipient = suite_r.create_recipient_context(enc, skr, info=info, pks=pks, psk=psk, psk_id=psk_id)
    pt = recipient.open(ct, aad=aad)  # ha l'aad

    print(pt)


for i in range(4):
    decription(f'Test vectors/Test{i}.json')
