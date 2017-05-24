from __future__ import absolute_import, print_function

from sentry.auth.providers.oauth2 import (
    OAuth2Callback, OAuth2Provider, OAuth2Login
)

from .constants import (
    AUTHORIZE_URL, ACCESS_TOKEN_URL, CLIENT_ID, CLIENT_SECRET, DATA_VERSION,
    SCOPE
)
from .views import FetchUser, OpenIDConfigureView


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

    def __init__(self, **config):
        super(OpenIDOAuth2Provider, self).__init__(**config)

    def get_configure_view(self):
        return OpenIDConfigureView.as_view()

    def get_auth_pipeline(self):
        return [
            OpenIDOAuth2Login(),
            OAuth2Callback(
                access_token_url=ACCESS_TOKEN_URL,
                client_id=self.client_id,
                client_secret=self.client_secret,
            ),
            FetchUser(),
        ]

    def get_refresh_token_url(self):
        return ACCESS_TOKEN_URL

    def build_config(self, state):
        return {}

    def build_identity(self, state):
        # https://developers.google.com/identity/protocols/OpenIDConnect#server-flow
        # data.user => {
        #      "iss":"accounts.google.com",
        #      "at_hash":"HK6E_P6Dh8Y93mRNtsDB1Q",
        #      "email_verified":"true",
        #      "sub":"10769150350006150715113082367",
        #      "azp":"1234987819200.apps.googleusercontent.com",
        #      "email":"jsmith@example.com",
        #      "aud":"1234987819200.apps.googleusercontent.com",
        #      "iat":1353601026,
        #      "exp":1353604926,
        #      "hd":"example.com"
        # }
        data = state['data']
        user_data = state['user']
        # TODO(dcramer): we should move towards using user_data['sub'] as the
        # primary key per the Google docs
        return {
            'id': user_data['email'],
            'email': user_data['email'],
            'name': user_data['email'],
            'data': self.get_oauth_data(data),
        }
