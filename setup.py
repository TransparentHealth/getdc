import os
from setuptools import setup, find_packages


setup(name="getdc",
      version="0.2.5",
      description="Library of tools for fetching and parsing x509 certificate from DNS and LDAP",
      long_description="""Outputs a JSON object of success or errors.\
          Requires dnspython and python-ldap to be installed and python-dev \
          libldap2-dev libsasl2-dev need to be installed on your system.""",
      author="Alan Viars",
      author_email="alan@transparenthealth.org",
      url="https://github.com/transparenthealth/getdc",
      download_url="https://github.com/transparenthealth/getdc/tarball/master",
      python_requires='>=3.11',
      install_requires=['dnspython', 'python-ldap', 'pyopenssl', 'cryptography', 'requests', 
                        'validate_email', 'cffi'],
      packages=['gdc',],
      include_package_data=True,
      scripts=['gdc/get_direct_certificate.py', 'gdc/parse_certificate.py', 'gdc/process_nppes_endpoint_file.py',
               'gdc/getdc_microservice.py', 'gdc/getdc_microservice_verbose.py']
      )
