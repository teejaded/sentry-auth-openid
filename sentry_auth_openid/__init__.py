from __future__ import absolute_import

from sentry.auth import register

from .provider import OpenIDOAuth2Provider

register('openid', OpenIDOAuth2Provider)
