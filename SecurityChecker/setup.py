from setuptools import setup

setup(
    name='securitychecker',
    version='1.0.0',
    description='Ultimate Website Security Analyzer - SSL/TLS, Headers, Vulnerabilities, DNS, Compliance',
    author='tahsan2544',
    author_email='tahsan2544@gmail.com',
    url='https://github.com/tahsan2544/SecurityChecker',
    py_modules=['securitycheck'],
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'securitycheck=securitycheck:main',
        ],
    },
    python_requires='>=3.7',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
)
