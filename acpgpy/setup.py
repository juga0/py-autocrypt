import os
from setuptools import setup

def main():
    with open(os.path.join("autocrypt", "__init__.py")) as f:
        for line in f:
            if "__version__" in line.strip():
                version = line.split("=", 1)[1].strip().strip('"')
                break

    setup(
        name='autocrypt',
        description='Autocrypt: E-mail Encryption for everyone example \
                     implementation',
        version=version,
        url='https://autocrypt.org',
        license='MIT license',
        platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],
        author='the Autocrypt team',
        author_email='autocrypt at lists.mayfirst.org',
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: POSIX',
                     'Operating System :: MacOS :: MacOS X',
                     'Topic :: Utilities',
                     'Intended Audience :: Developers',
                     'Programming Language :: Python'],
        packages=['autocrypt'],
        entry_points='''
            [console_scripts]
            autocrypt=autocrypt.cmdline_crypto:autocrypt_main
        ''',
        install_requires=[
            "click>=6.0",
             "six",
            "git+https://github.com/SecurityInnovation/PGPy.git@\
             24f5daee6eab9b334197a0a2d7035dfaf1521a58#egg=PGPy"
            ],
        zip_safe=False,
    )

if __name__ == '__main__':
    main()
