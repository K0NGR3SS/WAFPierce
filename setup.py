from setuptools import setup, find_packages
setup(
    name="wafpierce",
    version="1.0.0",
    packages=find_packages(),
    install_requires=['requests'],
    entry_points={'console_scripts': ['wafpierce=wafpierce.chain:main']}
)