from setuptools import setup

setup(
    name="net-admin",
    version="1.0.0",
    scripts=["net-admin.py"],
    install_requires=["colorama"],
    description="A tool to monitor TCP connections (IPv4 & IPv6)",
)
