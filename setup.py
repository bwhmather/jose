from setuptools import setup, find_packages


setup(
    name='jose',
    version='0.2.1',
    author='Demian Brecht',
    author_email='dbrecht@demonware.net',
    packages=find_packages(),
    url='https://github.com/Demonware/jose',
    description='An implementation of the JOSE draft',
    install_requires=[
        'pycrypto >= 2.6',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
    ],
    entry_points={
        'console_scripts': (
            'jose = jose:_cli',
        )
    },
    test_suite='jose.tests.suite',
)
