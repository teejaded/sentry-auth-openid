from __future__ import absolute_import

import pytest

from sentry.auth.exceptions import IdentityNotValid
from sentry.models import AuthIdentity, AuthProvider
from sentry.testutils import TestCase


class OpenIDOAuth2ProviderTest(TestCase):
    def setUp(self):
        self.org = self.create_organization(owner=self.user)
        self.user = self.create_user('foo@example.com')
        self.auth_provider = AuthProvider.objects.create(
            provider='OpenID',
            organization=self.org,
        )
        super(OpenIDOAuth2ProviderTest, self).setUp()

    def test_refresh_identity_without_refresh_token(self):
        auth_identity = AuthIdentity.objects.create(
            auth_provider=self.auth_provider,
            user=self.user,
            data={
                'access_token': 'access_token',
            }
        )

        provider = self.auth_provider.get_provider()

        with pytest.raises(IdentityNotValid):
            provider.refresh_identity(auth_identity)

    def test_build_config(self):
        provider = self.auth_provider.get_provider()
        state = {}
        result = provider.build_config(state)
        assert result == {
            'domains': ['example.com']
        }
