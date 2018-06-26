from __future__ import absolute_import, print_function

import logging

from sentry.auth.view import AuthView, ConfigureView
from sentry.utils import json

from .constants import (
    DOMAIN_WHITELIST, ERR_INVALID_RESPONSE, ERR_INVALID_DOMAIN, OAUTH_NAME
)
from .utils import urlsafe_b64decode

logger = logging.getLogger('sentry.auth.openid')


class FetchUser(AuthView):
    def __init__(self, *args, **kwargs):
        super(FetchUser, self).__init__(*args, **kwargs)

    def extract_domain(email):
        return email.rsplit('@', 1)[-1]

    def dispatch(self, request, helper):
        data = helper.fetch_state('data')

        try:
            access_token = data['access_token']
        except KeyError:
            logger.error('Missing access_token in OAuth response: %s' % data)
            return helper.error(ERR_INVALID_RESPONSE)

        try:
            payload = urlsafe_b64decode(access_token.split('.')[1])
        except Exception as exc:
            logger.error(u'Unable to decode access_token: %s' % exc, exc_info=True)
            return helper.error(ERR_INVALID_RESPONSE)

        try:
            payload = json.loads(payload)
        except Exception as exc:
            logger.error(u'Unable to load access_token payload: %s' % exc, exc_info=True)
            return helper.error(ERR_INVALID_RESPONSE)

        if not payload.get('email'):
            logger.error('Missing email in access_token payload: %s' % access_token)
            return helper.error(ERR_INVALID_RESPONSE)

        # support legacy style domains with pure domain regexp
        if self.version is None:
            domain = self.extract_domain(payload['email'])
        else:
            domain = payload.get('hd')

        if domain is None:
            return helper.error(ERR_INVALID_DOMAIN % (OAUTH_NAME, domain,))

        if domain not in DOMAIN_WHITELIST:
            return helper.error(ERR_INVALID_DOMAIN % (OAUTH_NAME, domain,))

        if self.domains and domain not in self.domains:
            return helper.error(ERR_INVALID_DOMAIN % (OAUTH_NAME, domain,))

        helper.bind_state('domain', domain)
        helper.bind_state('user', payload)

        return helper.next_step()


class OpenIDConfigureView(ConfigureView):
    def dispatch(self, request, organization, auth_provider):
        config = auth_provider.config
        return self.render('sentry_auth_openid/configure.html', {
            'oauth_name': config.get('oauth_name'),
            'authorize_url': config.get('authorize_url'),
            'access_token_url': config.get('access_token_url'),
            'domain_whitelist': config.get('domain_whitelist'),
            'client_id': config.get('client_id'),
        })
