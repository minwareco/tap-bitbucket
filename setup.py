#!/usr/bin/env python

from setuptools import setup, find_packages

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
          'gitlocal@git+https://{}@github.com/minwareco/gitlocal.git'.format(os.environ.get("GITHUB_TOKEN", ""))
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
