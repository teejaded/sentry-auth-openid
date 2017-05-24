OpenID Connect for Sentry
=========================

An SSO provider for Sentry which enables OpenID Connect authentication.  This is a fork off of the Google Apps auth module.

Install
-------

::

    $ pip install https://github.com/TableflippersAnonymous/sentry-auth-openid/archive/master.zip

Setup
-----

We'll assume you already have an OpenID Connect capable IDP.  I prefer Okta.

In the **Authorized redirect URIs** add the SSO endpoint for your installation::

    https://sentry.example.com/auth/sso/

You will need to get the Authorize and Token URLs for your IDP.  If they provide you with a config or metadata URL, you can find the
authorize URL and token URL in that.  If you only have an issuer URL, you can append `/.well-known/openid-configuration` to the end
to get a metadata URL.  `OPENID_AUTHORIZE_URL` should be set to the value of the `authorization_endpoint` key in the metadata JSON,
and `OPENID_TOKEN_URL` should be set to the `token_endpoint` key in the metadata JSON.

Finally, obtain the API keys and plug them into your ``sentry.conf.py``:

.. code-block:: python

    OPENID_AUTHORIZE_URL = ""

    OPENID_TOKEN_URL = ""

    OPENID_CLIENT_ID = ""

    OPENID_CLIENT_SECRET = ""

