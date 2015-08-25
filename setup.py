# -*- coding: utf-8 -*-
# !/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='wechat-python-sdk',
    version='0.6.1',
    keywords=('wechat', 'sdk', 'wechat sdk'),
    description=u'微信公众平台Python开发包',
    long_description=open("README.rst").read(),
    license='BSD License',

    url='https://github.com/bowenpay/wechat-python-sdk',
    author='doraemonext jingpingyi',
    author_email='doraemonext@gmail.com, jingping.yi@gmail.com',

    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    install_requires=map(lambda x: x.replace('==', '>='), open("requirements.txt").readlines()),
)
