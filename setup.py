# rs-utils is available under the MIT License. https://github.com/roundservices/rs-utils/
# Copyright (c) 2021, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

from setuptools import setup

setup(
    name='rs-keycloak',
    version='1.0.20220501',
    description='Python utilities for Keycloak',
    url='git@github.com:RoundServices/rs-keycloak.git',
    author='Round Services',
    author_email='ggallard@roundservices.biz',
    license='MIT License',
    install_requires=['python-keycloak>=0.26.1'],
    packages=['rs.keycloak'],
    zip_safe=False,
    python_requires='>=3.0'
)
