from setuptools import setup, find_packages

setup(
    name='pydbd',
    version='0.0',
    description='experimental openxt python dbd replacement',
    url='',
    author='Chris Patterson',
    author_email='pattersonc@ainfosec.com',
    license='GPLv2',
    packages=find_packages(),
    package_data={ },
    scripts = ['dbd', 'db-read', 'db-write', 'db-cat', 'db-nodes', 'db-exists', 'db-rm', 'db-inject', 'db-ls', 'db-dump'],
)
