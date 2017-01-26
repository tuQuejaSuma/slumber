import requests
from requests.auth import AuthBase, HTTPBasicAuth

from . import exceptions


class TokenAuth(AuthBase):
    """
    Token based Authentication, intended to work with djangorestframework
    Makes a .post() call to a designated api_auth_url to retrieve a token to
    use as authorization
    """
    TOKEN_NAME = 'Token'  # Standart django rest config
    token = None

    def __init__(self, username, password, auth_url):
        self.username = username
        self.password = password
        payload = {'username': username, 'password': password}
        res = requests.post(auth_url, data=payload)
        if res.status_code != requests.codes.ok:
            raise exceptions.SlumberAuthenticationError(
                "Failed to retrieve token"
            )
        self.token = res.json().get(self.TOKEN_NAME.lower(), None)
        if not self.token:
            raise exceptions.SlumberAuthenticationError(
                "Couldn't read token from '%s'" % auth_url
            )

    def __call__(self, r):
        assert(self.token)
        # modify and return the request
        r.headers['Authorization'] = '{} {}'.format(self.TOKEN_NAME,
                                                    self.token)
        return r
