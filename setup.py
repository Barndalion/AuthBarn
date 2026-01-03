from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="AuthBarn",
    version="0.2.8",
    author="Darell Barnes",
    author_email="darellbarnes450@gmail.com",
    description="User authentication and role-based management.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Barndalion/AuthBarn",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "AuthBarn": ["data/*.json", "logfiles/*.log"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "bcrypt",
        "PyJWT",
        "mysql-connector-python",
        "python-dotenv",
    ],
    python_requires=">=3.6",
)
