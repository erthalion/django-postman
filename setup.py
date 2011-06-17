from setuptools import setup, find_packages

setup(
    name='django-postman',
    version=__import__('postman').__version__,
    description = 'A messaging application for Django',
    author = 'Patrick Samson',
    license = 'BSD',
    packages=find_packages(exclude=('docs',)),
    include_package_data=True,
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    install_requires = [
        'Django',
    ],
)

