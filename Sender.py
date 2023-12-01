import base64
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.consts import Mode
import json


def bytes_to_base64(byte_data):
    return base64.b64encode(byte_data).decode('utf-8')


def base64_to_bytes(base64_string):
    return base64.b64decode(base64_string.encode('utf-8'))


def encription(mode=0):
    suite_s = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
    )

    info = b""
    psk_id = b""
    psk = b""
    ikm_s = None
    ikm_r = b""
    aad = b""
    sks = None
    ############### BASE MODE ########################
    if mode == 0:
        info = b"info_base_mode"
        ikm_r = b"ikm_receiver_base_mode"
        aad = b"aad_base_mode"
    ############### PSK MODE ########################
    elif mode == 1:
        info = b"info_psk_mode"
        ikm_r = b"ikm_receiver_psk_mode"
        aad = b"aad_psk_mode"
        psk = b"psk_psk_mode"
        psk_id = b"psk_id_psk_mode"
    ############### AUTH MODE ########################
    elif mode == 2:
        info = b"info_auth_mode"
        ikm_r = b"ikm_receiver_auth_mode"
        ikm_s = b"ikm_sender_auth_mode"
        aad = b"aad_auth_mode"
    ############### PSK AUTH MODE ########################
    elif mode == 3:
        info = b"info_psk_auth_mode"
        ikm_r = b"ikm_receiver_psk_auth_mode"
        ikm_s = b"ikm_sender_psk_auth_mode"
        aad = b"aad_base_mode"
        psk = b"psk_psk_auth_mode"
        psk_id = b"psk_id_psk_auth_mode"

    if ikm_s is not None:
        sks = suite_s.kem.derive_key_pair(ikm_s).private_key  # serve per il sks per AUTH peivate key sender
    # serve per il sks per AUTH
    pkr = suite_s.kem.derive_key_pair(ikm_r).public_key  # chiave pubblica del receiver
    enc, sender = suite_s.create_sender_context(pkr, info=info, sks=sks,
                                                psk=psk,
                                                psk_id=psk_id)  # psk= segreto condiviso per psk mode, qui abbiamo anche il eks = ephimeral
    ct = sender.seal(b"Prova{mode}", aad=aad)  # seal ha l'aad
    # Write to the JSON file

    data = {
        "info": {
            "psk": bytes_to_base64(psk),
            "psk_id": bytes_to_base64(psk_id),
        },
        "pub_data": {
            "mode": mode,
            "info": bytes_to_base64(info),
            "aad": bytes_to_base64(aad),
            "ikm_s": bytes_to_base64(ikm_s) if ikm_s is not None else None,
            "ikm_r": bytes_to_base64(ikm_r),
            "enc": bytes_to_base64(enc),
            "ct": bytes_to_base64(ct),
        }
    }

    with open(f'Test vectors/Test{mode}.json', 'w') as file:
        json.dump(data, file, indent=2)

    print("JSON file created successfully.")

for i in range (4):
    encription(i)
