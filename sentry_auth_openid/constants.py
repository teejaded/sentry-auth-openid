from __future__ import absolute_import, print_function

from django.conf import settings


AUTHORIZE_URL = getattr(settings, 'OPENID_AUTHORIZE_URL', None)

ACCESS_TOKEN_URL = getattr(settings, 'OPENID_TOKEN_URL', None)

CLIENT_ID = getattr(settings, 'OPENID_CLIENT_ID', None)

CLIENT_SECRET = getattr(settings, 'OPENID_CLIENT_SECRET', None)

OAUTH_NAME = getattr(settings, 'OAUTH_NAME', 'IBMid')

ERR_INVALID_DOMAIN = 'The domain for your %s account (%s) is not allowed to authenticate with this provider.'

ERR_INVALID_RESPONSE = 'Unable to fetch user information.  Please check the log.'

SCOPE = 'openid'

DOMAIN_WHITELIST = frozenset(getattr(settings, 'OPENID_DOMAIN_WHITELIST', ['ibm.com', 'us.ibm.com']) or [])

DATA_VERSION = ''
