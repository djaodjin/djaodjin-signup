"""
WSGI config for testsite project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/howto/deployment/wsgi/
"""
import os, signal

from django.core.wsgi import get_wsgi_application


def save_coverage(*args):
    sys.stderr.write("saving coverage\n")
    cov.stop()
    cov.save()

if os.getenv('DJANGO_COVERAGE'):
    import atexit, sys
    import coverage
    data_file=os.path.join(os.getenv('DJANGO_COVERAGE'),
        ".coverage.%d" % os.getpid())
    cov = coverage.coverage(data_file=data_file)
    sys.stderr.write("start recording coverage in %s\n" % str(data_file))
    cov.set_option("run:relative_files", True)
    cov.start()
    atexit.register(save_coverage)
    try:
        signal.signal(signal.SIGTERM, save_coverage)
    except ValueError as e:
        # trapping signals does not work with manage
        # trying to do so fails with
        # ValueError: signal only works in main thread
        pass

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "testsite.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
#pylint: disable=invalid-name
application = get_wsgi_application()
