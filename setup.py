from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='ntlm_parser',
      version='0.1',
      description='A simple ntlm response parser',
      url='http://github.com/storborg/funniest',
      author='Andrea Titton',
      author_email='andreatitton96@gmail.com',
      long_description=long_description,
      license='MIT',
      zip_safe=False)