from __future__ import absolute_import, print_function

from six.moves.urllib.parse import parse_qsl
from sentry.http import safe_urlopen, safe_urlread
from sentry.utils import json
from sentry.utils.http import absolute_uri
from sentry.auth.providers.oauth2 import (
    OAuth2Callback, OAuth2Provider, OAuth2Login
)

from .constants import (
    AUTHORIZE_URL, ACCESS_TOKEN_URL, CLIENT_ID, CLIENT_SECRET, SCOPE
)
from .views import FetchUser, OpenIDConfigureView

import base64


class OpenIDOAuth2Callback(OAuth2Callback):
    access_token_url = None
    client_id = None
    client_secret = None

    def __init__(self, **config):
        super(OpenIDOAuth2Callback, self).__init__(**config)

    def exchange_token(self, request, helper, code):
        headers = {
            'authorization': 'Basic ' + base64.b64encode(CLIENT_ID + ':' + CLIENT_SECRET)
        }
        # TODO: this needs the auth yet
        data = self.get_token_params(
            code=code,
            redirect_uri=absolute_uri(helper.get_redirect_url()),
        )
        req = safe_urlopen(self.access_token_url, data=data, headers=headers)
        body = safe_urlread(req)
        if req.headers['Content-Type'].startswith('application/x-www-form-urlencoded'):
            return dict(parse_qsl(body))
        return json.loads(body)


class OpenIDOAuth2Login(OAuth2Login):
    authorize_url = AUTHORIZE_URL
    client_id = CLIENT_ID
    scope = SCOPE

    def __init__(self):
        super(OpenIDOAuth2Login, self).__init__()

    def get_authorize_params(self, state, redirect_uri):
        params = super(OpenIDOAuth2Login, self).get_authorize_params(
            state, redirect_uri
        )
        # TODO(dcramer): ideally we could look at the current resulting state
        # when an existing auth happens, and if they're missing a refresh_token
        # we should re-prompt them a second time with ``approval_prompt=force``
        params['approval_prompt'] = 'force'
        params['access_type'] = 'offline'
        return params


class OpenIDOAuth2Provider(OAuth2Provider):
    name = 'OpenID'
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    access_token_url = ACCESS_TOKEN_URL

    def __init__(self, **config):
        super(OpenIDOAuth2Provider, self).__init__(**config)

    def get_configure_view(self):
        return OpenIDConfigureView.as_view()

    def get_auth_pipeline(self):
        return [
            OpenIDOAuth2Login(),
            OpenIDOAuth2Callback(
                access_token_url=ACCESS_TOKEN_URL,
                client_id=self.client_id,
                client_secret=self.client_secret,
            ),
            FetchUser(),
        ]

    def get_refresh_token_url(self):
        return self.access_token_url

    def build_identity(self, state):
        data = state['data']
        user_data = state['user']
        # TODO(dcramer): we should move towards using user_data['sub'] as the
        # primary key per the Google docs
        return {
            'id': user_data['sub'],
            'email': user_data['email'],
            'name': user_data['name'],
            'data': self.get_oauth_data(data),
        }
