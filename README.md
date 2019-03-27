# ntlm_parser

Most of the credit goes to [Adam Seering](https://github.com/aseering) and his [this gist](https://gist.github.com/aseering/829a2270b72345a1dc42#file-ntlmdecoder-py). This code is just a python3 version, of his with the addition of some feautures and pip packaging.

## Installation

Just,

```bash
pip install ntlm_parser
```

like usual

## Usage

The tool can be used, as the original from the command line:

```bash
echo 'TlRM...' | python ntlm_parser/parser.py
```

as a disclaimer this is not a command line tool, it ust reads `stdout`.

If you want to use it as a python library just go ahead and:

```python
from ntlm_parser import parser
auth_str = 'TLRM...'
data = parser(auth_str)

```

A bunch of stuff will be printed and you will also have it as a returned `dict`.