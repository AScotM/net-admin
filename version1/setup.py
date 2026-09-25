from setuptools import setup

setup(
    name="net-admin",
    version="2.0.0",
    py_modules=["net_admin"],
    entry_points={
        "console_scripts": [
            "net-admin=net_admin:main",
        ],
    },
    python_requires=">=3.10",
    description="Linux TCP connection monitor using /proc/net/tcp and /proc/net/tcp6",
)
