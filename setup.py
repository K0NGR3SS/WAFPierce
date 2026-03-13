from setuptools import setup, find_packages
setup(
    name="wafpierce",
    version="1.4",
    packages=find_packages(),
    install_requires=['requests', 'urllib3', 'certifi', 'charset-normalizer', 'idna', 'cryptography'],
    entry_points={'console_scripts': ['wafpierce=wafpierce.chain:main']}
)