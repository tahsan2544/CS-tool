from setuptools import setup

setup(
    name='emailanalyzer',
    version='1.0.0',
    description='Email Deliverability Analyzer - SPF, DKIM, DMARC, MX, BIMI',
    author='tahsan2544',
    author_email='tahsan2544@gmail.com',
    url='https://github.com/tahsan2544/CS-Tools',
    py_modules=['emailanalyzer'],
    install_requires=[
        'requests>=2.31.0',
        'colorama>=0.4.6',
        'dnspython>=2.4.0',
    ],
    entry_points={
        'console_scripts': [
            'emailanalyzer=emailanalyzer:main',
        ],
    },
    python_requires='>=3.7',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Email',
    ],
)
