from setuptools import setup, find_packages

setup(
    name='id_token_verify',
    version='0.1',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/its-dirg/id_token_verify',
    license='Apache 2.0',
    author='Rebecka Gulliksson',
    author_email='rebecka.gulliksson@umu.se',
    description='Utility/service for verifying signed OpenID Connect ID Tokens.',
    install_requires=['oic', 'requests']
)
