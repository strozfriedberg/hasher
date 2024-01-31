import setuptools


setuptools.setup(
    name='hasher',
    version='0.1.0',
    author='Joel Uckelman <joel.uckelman@aon.co.uk>',
    packages=['hasher'],
    package_data={
        'hasher': ['libhasher.so', 'libhasher.dylib']
    },
    include_package_data=True,
    has_ext_modules=lambda: True
)
