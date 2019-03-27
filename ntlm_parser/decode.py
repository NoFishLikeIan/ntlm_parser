import sys
import base64
import struct
import string
import collections

from functools import partial

from .parsers import parse_request_type, parse_response_type, parse_challenge_type


process_fn = {
    1: parse_request_type,
    2: parse_challenge_type,
    3: parse_response_type
}

possible_messages = ['request', 'challenge', 'response']


def decode(passed_auth=None):
    parsed_data = {
        'valid_sig': False,
        'message': 'unfound'
    }

    auth = sys.stdin.read() if passed_auth is None else passed_auth

    # Converting
    try:
        auth_b64 = base64.b64decode(auth)
    except Exception as e:
        raise Exception(f'Input is not a base64 string, failed with:\t{e}')

    # Parsing signature
    signature = auth_b64[:8]
    if signature == b'NTLMSSP\x00':
        print('Authentication signature parsed correctly')
    else:
        raise Exception(f'Found as signature ${signature} instead of NTLMSSP\x00')

    parsed_data['valid_sig'] = True

    # Parsing message
    message_portion = auth_b64[8:12]
    message_id = struct.unpack('<i', message_portion)[0]
    if (-1 < message_id - 1 < 3):
        message_type = possible_messages[message_id - 1]

    parsed_data['message'] = message_type
    print(f'Message type:\t{message_type}')
    
    if message_id in process_fn:
        parsed_structure = process_fn[message_id](auth_b64)
        parsed_data['structure'] = parsed_structure

    else:
        raise Exception(f"Unknown message structure.  Have a raw (hex-encoded) message:\n{auth_b64.decode('hex')}")
    
    return parsed_data