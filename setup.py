from distutils.core import setup
import signup

setup(
    name='signup',
    version=signup.__version__,
    author='The DjaoDjin Team',
    author_email='support@djaodjin.com',
    packages=['signup',
              'signup.backends',
              ],
    url='https://github.com/djaodjin/djaodjin-signup/',
    license='BSD',
    description="DjaoDjin's Implementation of Frictionless Sign Up",
    long_description=open('README.md').read(),
)
