from setuptools import setup

setup(
    name='uptimechecker',
    version='2.0.0',
    description='Advanced Website Uptime & Availability Monitor - DNS, SSL, CDN, HTTP/2/3, SLA, Circuit Breaker',
    author='tahsan2544',
    author_email='tahsan2544@gmail.com',
    url='https://github.com/tahsan2544/CS-Tools',
    py_modules=['uptimechecker'],
    install_requires=[
        'requests>=2.31.0',
        'rich>=13.0.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'uptimechecker=uptimechecker:main',
        ],
    },
    python_requires='>=3.7',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Monitoring',
    ],
)
