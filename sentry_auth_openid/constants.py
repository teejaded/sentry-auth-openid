from __future__ import absolute_import, print_function

from django.conf import settings


AUTHORIZE_URL = getattr(settings, 'OPENID_AUTHORIZE_URL', None)

ACCESS_TOKEN_URL = getattr(settings, 'OPENID_TOKEN_URL', None)

CLIENT_ID = getattr(settings, 'OPENID_CLIENT_ID', None)

CLIENT_SECRET = getattr(settings, 'OPENID_CLIENT_SECRET', None)

ERR_INVALID_RESPONSE = 'Unable to fetch user information.  Please check the log.'

SCOPE = 'openid email'

DATA_VERSION = '1'
