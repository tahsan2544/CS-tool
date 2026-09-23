from setuptools import setup, find_packages
import os

with open(os.path.join(os.path.dirname(__file__), "requirements.txt"), encoding="utf-8") as f:
    requirements = [l.strip() for l in f if l.strip() and not l.startswith("#")]

setup(
    name="upgrade-advisor",
    version="1.0.0",
    description="Aggregate CS Tools scores into a prioritized website upgrade roadmap",
    author="tahsan2544",
    license="MIT",
    py_modules=["upgradetool"],
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "upgradeadvisor=upgradetool:main",
        ],
    },
    python_requires=">=3.7",
)
