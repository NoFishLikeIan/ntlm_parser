import struct
import collections

from .opt_structures import parse_str_structure, stringify_flags, StrStruct, clean

targ_fields = ["TERMINATOR", "Server name", "AD domain name", "FQDN", "DNS domain name", "Parent DNS domain", "Server Timestamp"]
targ_dict = dict(zip(range(len(targ_fields)), targ_fields))

target_field_types = collections.defaultdict(lambda: 'unknown', targ_dict)


def parse_request_type(auth_b64):
    header_flags = struct.unpack('<i', auth_b64[12:16])[0]
    domain = parse_str_structure('Domain', auth_b64, 16)
    work = parse_str_structure('Workstation', auth_b64, 24)

    os = parse_str_structure('Os version', auth_b64, 32, simple=True)
    string_flags = stringify_flags(header_flags)
    print(f'Flags: 0x{header_flags} [{string_flags}]')
    return {'flags': string_flags.split(', '), 'domain': domain, 'work': work}


def parse_challenge_type(auth_b64):
    header_tuple = struct.unpack('<hhiiQ', auth_b64[12:32])
    print(f'Target name: {StrStruct(header_tuple[0:3], auth_b64)}')
    print(f'Challenge: 0x{header_tuple[4]}')

    flags = header_tuple[3]
    
    context = parse_str_structure('Context', auth_b64, 32)

    chunk = auth_b64[40:48]
    records = []
    if len(chunk) == 8:
        header_tuple = struct.unpack('<hhi', chunk)
        target = StrStruct(header_tuple, auth_b64)

        output = f'Target: [block] ({target.length}b @{target.offset})'

        if target.alloc != target.length:
            output += f' alloc: {int(target.alloc, base = 16)}'

        print(output)

        raw = target.raw
        pos = 0

        while pos + 4 < len(raw):
            record_header = struct.unpack('<hh', raw[pos: pos+4])
            record_type_id = record_header[0]
            record_type = target_field_types[record_type_id] if record_type_id in target_field_types else 'unknown'
            record_size = record_header[1]
            substitute = raw[pos+4: pos + 4 + record_size]
            
            print_sub = clean(substitute)
            print(f'\t{record_type} ({record_type_id}): {print_sub}')
            records.append((record_type_id, print_sub))
            pos += 4 + record_size
        
    os = parse_str_structure('OS Ver', auth_b64, 48, simple=True)
    print(f'Flags: {hex(flags)} [{stringify_flags(flags)}]')

    return {'flags': stringify_flags(flags).split(', '), 'context': context, 'records': records}


# TODO: This could be improved
def parse_response_type(auth_b64):
    header_tuple = struct.unpack('<hhihhihhihhihhi', auth_b64[12:52])
    parsed_headers =  {
        "LM Resp": StrStruct(header_tuple[0:3], auth_b64),
        "NTLM Resp": StrStruct(header_tuple[3:6], auth_b64),
        "Target Name": StrStruct(header_tuple[6:9], auth_b64),
        "User Name": StrStruct(header_tuple[9:12], auth_b64),
        "Host Name": StrStruct(header_tuple[12:15], auth_b64)
        }

    print(f"LM Resp: {StrStruct(header_tuple[0:3], auth_b64)}")
    print(f"NTLM Resp: {StrStruct(header_tuple[3:6], auth_b64)}")
    print(f"Target Name: {StrStruct(header_tuple[6:9], auth_b64)}")
    print(f"User Name: {StrStruct(header_tuple[9:12], auth_b64)}")
    print(f"Host Name: {StrStruct(header_tuple[12:15], auth_b64)}")

    key = parse_str_structure('Session key', auth_b64, 52)
    os = parse_str_structure('OS Ver', auth_b64, 64, simple=True)

    chunk = auth_b64[60:64]
    if len(chunk) == 4:
        flags = struct.unpack('<i', chunk)[0]
        stringified_flags = stringify_flags(flags)
        print(f'Flags: 0x{flags} [{stringified_flags}]')

    else:
        print('Flags omitted')

    out = dict(**parsed_headers)
    out['key'] = key
    out['flags'] = stringified_flags.split(', ')

    return out
