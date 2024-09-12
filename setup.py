from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

with open('README.md') as f:
    long_description = f.read()

setup(
    name='power-platform-security-assessment',
    version='0.1.0',
    description='Power Platform Security Assessment Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Nokod Security',
    author_email='support@nokodsecurity.com',
    url='https://github.com/Nokod/power-platform-security-assessment',
    packages=find_packages(),
    install_requires=requirements,
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'power-platform-security-assessment=power_platform_security_assessment.security_assessment_tool:main',
        ],
    },
)
