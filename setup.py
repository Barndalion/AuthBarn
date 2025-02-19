from setuptools import setup,find_packages

setup(
    name="AuthBarn",  
    version="0.1.4",
    author="Darell Barnes",
    author_email="darellbarnes450@gmail.com",
    description="User authentication and role-based management.",
    long_description=open("READme.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Barndalion/AuthBarn",
    packages=find_packages(),
    include_package_data=True,  
    package_data={
        "authbarn": ["data/*.json", "logfiles/*.log"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[], 
    python_requires=">=3.6",
)