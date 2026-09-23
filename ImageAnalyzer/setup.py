from setuptools import setup

setup(
    name='imageanalyzer',
    version='1.0.0',
    description='Image Optimization Analyzer - Format, Size, Responsive, Lazy Loading',
    author='tahsan2544',
    author_email='tahsan2544@gmail.com',
    url='https://github.com/tahsan2544/CS-Tools',
    py_modules=['imageanalyzer'],
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'imageanalyzer=imageanalyzer:main',
        ],
    },
    python_requires='>=3.7',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Multimedia :: Graphics',
    ],
)
