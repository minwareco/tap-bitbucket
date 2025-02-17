#!/usr/bin/env python

from setuptools import setup, find_packages
import os

UTILS_VERSION = "81f3a1c44838af09d0f426a1c2f59852b6f1014a"

setup(name='tap-bitbucket',
      version='1.0.0',
      description='Singer.io tap for extracting data from the BitBucket API',
      author='minware',
      url='http://www.minware.com',
      classifiers=['Programming Language :: Python :: 3 :: Only'],
      py_modules=['tap_bitbucket'],
      install_requires=[
          'singer-python==5.12.1',
          'requests==2.20.0',
          'psutil==5.8.0',
          'debugpy==1.5.1',
          'PyJWT==2.8.0',
          'cryptography==42.0.1',
          'minware_singer_utils@git+https://{}github.com/minwareco/minware-singer-utils.git@{}'.format(
              "{}@".format(os.environ.get("GITHUB_TOKEN")) if os.environ.get("GITHUB_TOKEN") else "",
              UTILS_VERSION
          )
      ],
      extras_require={
          'dev': [
              'pylint',
              'ipdb',
              'nose',
          ]
      },
      entry_points='''
          [console_scripts]
          tap-bitbucket=tap_bitbucket:main
      ''',
      packages=['tap_bitbucket'],
      package_data = {
          'tap_bitbucket': ['tap_bitbucket/schemas/*.json']
      },
      include_package_data=True
)
