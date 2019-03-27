import string
import struct
import collections

VALID = set(string.ascii_letters + string.digits + string.punctuation)


def clean(x): return ''.join((s if s in VALID else '?') for s in x)


def prittyprint(elem_1, elem_2, elem_3, elem_4, elem_5):
    return f'{elem_1} "{elem_2}"  [{elem_3}] ({elem_4}b @{elem_5})'


class StrStruct(object):
    def __init__(self, pos_tup, raw):
        length, alloc, offset = pos_tup
        self.length = length
        self.alloc = alloc
        self.offset = offset
        self.raw = raw[offset:offset+length]
        self.utf16 = False

        if len(self.raw) >= 2 and self.raw[1] == '\0':
            self.string = self.raw.decode('utf-16')
            self.utf16 = True
        else:
            self.string = self.raw

    def __repr__(self):
        st = "%s'%s' [%s] (%db @%d)" % ('u' if self.utf16 else '',
                                        clean(self.string),
                                        self.raw.hex(),
                                        self.length, self.offset)
        elems = ['u' if self.utf16 else '',
                 clean(self.string),
                 self.raw.hex(),
                 self.length,
                 self.offset, ]

        st = prittyprint(*elems)

        if self.alloc != self.length:
            st += f" alloc: {self.alloc}"

        return st


def parse_str_structure(name, input_str, offset, length=8, simple=False):
    chunk = input_str[offset:offset + length]
    if len(chunk) == length:
        if simple is False:
            structure = struct.unpack('<hhi', chunk)
            parsedStructure = StrStruct(structure, input_str)
        else:
            parsedStructure = clean(chunk)

        print(f'{name} -> {parsedStructure}')
        return parsedStructure
    else:
        parsedStructure = 'omitted'
        print(f'{name} -> [{parsedStructure}]')
        return parsedStructure


# TODO: Check!
raw_flags = {
    0x00000001:	'Negotiate Unicode',
    0x00000002:	'Negotiate OEM',
    0x00000004:	'Request Target',
    0x00000008:	'unknown_1',
    0x00000010:	'Negotiate Sign',
    0x00000020:	'Negotiate Seal',
    0x00000040:	'Negotiate Datagram Style',
    0x00000080:	'Negotiate Lan Manager Key1',
    0x00000100:	'Negotiate Netware',
    0x00000200:	'Negotiate NTLM',
    0x00000400:	'unknown_2',
    0x00000800:	'Negotiate Anonymous',
    0x00001000:	'Negotiate Domain Supplied',
    0x00002000:	'Negotiate Workstation Supplied',
    0x00004000:	'Negotiate Local Call',
    0x00008000:	'Negotiate Always Sign',
    0x00010000:	'Target Type Domain',
    0x00020000:	'Target Type Server',
    0x00040000:	'Target Type Share',
    0x00080000:	'Negotiate NTLM2 Key',
    0x00100000:	'Request Init Response',
    0x00200000:	'Request Accept Response',
    0x00400000:	'Request Non-NT Session Key',
    0x00800000:	'Negotiate Target Info',
    0x01000000:	'unknown_3',
    0x02000000:	'unknown_4',
    0x04000000:	'unknown_5',
    0x08000000:	'unknown_6',
    0x10000000:	'unknown_7',
    0x20000000:	'Negotiate 128',
    0x40000000:	'Negotiate Key Exchange',
    0x80000000:	'Negotiate 56',
}

flags = collections.defaultdict( lambda: 'unknown', raw_flags)


def flag_array(instance_flags):
    '''
    Pretty print the flags, if the flag is not present return 'unknown'.
    Notice that if:\n
    a = 0x80000000\n
    b = 2147483648\n
    a == b // True
    '''
    if not isinstance(instance_flags, list):
        instance_flags = [instance_flags] 
        
    messages = []
    for flag in instance_flags:
        message = flags[flag]
        messages.append(message)

    return messages

def stringify_flags(instance_flags):
    found_flags = flag_array(instance_flags)
    return ', '.join(map(str, found_flags))

