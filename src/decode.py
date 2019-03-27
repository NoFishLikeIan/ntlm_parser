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

int16 = partial(int, base=16)


def integerize(bytelike): return int16(bytelike)


flags = {
    b'0x00000001':	'Negotiate Unicode',
    b'0x00000002':	'Negotiate OEM',
    b'0x00000004':	'Request Target',
    b'0x00000008':	'unknown_1',
    b'0x00000010':	'Negotiate Sign',
    b'0x00000020':	'Negotiate Seal',
    b'0x00000040':	'Negotiate Datagram Style',
    b'0x00000080':	'Negotiate Lan Manager Key1',
    b'0x00000100':	'Negotiate Netware',
    b'0x00000200':	'Negotiate NTLM',
    b'0x00000400':	'unknown_2',
    b'0x00000800':	'Negotiate Anonymous',
    b'0x00001000':	'Negotiate Domain Supplied',
    b'0x00002000':	'Negotiate Workstation Supplied',
    b'0x00004000':	'Negotiate Local Call',
    b'0x00008000':	'Negotiate Always Sign',
    b'0x00010000':	'Target Type Domain',
    b'0x00020000':	'Target Type Server',
    b'0x00040000':	'Target Type Share',
    b'0x00080000':	'Negotiate NTLM2 Key',
    b'0x00100000':	'Request Init Response',
    b'0x00200000':	'Request Accept Response',
    b'0x00400000':	'Request Non-NT Session Key',
    b'0x00800000':	'Negotiate Target Info',
    b'0x01000000':	'unknown_3',
    b'0x02000000':	'unknown_4',
    b'0x04000000':	'unknown_5',
    b'0x08000000':	'unknown_6',
    b'0x10000000':	'unknown_7',
    b'0x20000000':	'Negotiate 128',
    b'0x40000000':	'Negotiate Key Exchange',
    b'0x80000000':	'Negotiate 56',
}

flags_int = dict(zip(map(int16, flags.keys()), flags.values()))

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
    else:
        print(f"Unknown message structure.  Have a raw (hex-encoded) message:\n{auth_b64.decode('hex')}")
