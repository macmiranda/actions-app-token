from collections import namedtuple, Counter
from github3 import GitHub
from pathlib import Path
from cryptography.hazmat.backends import default_backend
import time
import json
import jwt
import requests
from typing import List
import os
import base64

class GitHubApp(GitHub):
    """
    This is a small wrapper around the github3.py library

    Provides some convenience functions for testing purposes.
    """

    def __init__(self, app_pem, app_id):
        super().__init__()
        self.app_id = app_id
        self.app_pem = app_pem

    def get_app(self):
        client = GitHub()
        client.login_as_app(private_key_pem=base64.b64decode(self.app_pem),
                            app_id=self.app_id)
        return client

    def get_installation(self, installation_id):
        "login as app installation without requesting previously gathered data."

        client = GitHub()
        client.login_as_app_installation(private_key_pem=base64.b64decode(self.app_pem),
                                            app_id=self.app_id,
                                            installation_id=installation_id)
        return client

    def get_jwt(self):
        """
        This is needed to retrieve the installation access token (for debugging).

        Useful for debugging purposes.  Must call .decode() on returned object to get string.
        """
        now = self._now_int()
        payload = {
            "iat": now,
            "exp": now + (60),
            "iss": self.app_id
        }
        private_key = default_backend().load_pem_private_key(base64.b64decode(self.app_pem), None)
        return jwt.encode(payload, private_key, algorithm='RS256')

    def get_installation_id(self):
        "https://developer.github.com/v3/apps/#find-repository-installation"
        url = f'https://api.github.com/app/installations'
        headers = {'Authorization': f'Bearer {self.get_jwt().decode()}',
                   'Accept': 'application/vnd.github+json'}
        response = requests.get(url=url, headers=headers)
        if response.status_code != 200:
            raise Exception(f'Status code : {response.status_code}, {response.json()}')
        return response.json()[0]['id']

    def get_installation_access_token(self, installation_id):
        "Get the installation access token for debugging."

        url = f'https://api.github.com/app/installations/{installation_id}/access_tokens'
        headers = {'Authorization': f'Bearer {self.get_jwt().decode()}',
                   'Accept': 'application/vnd.github+json'}

        response = requests.post(url=url, headers=headers)
        if response.status_code != 201:
            raise Exception(f'Status code : {response.status_code}, {response.json()}')
        return response.json()['token']

    def _extract(self, d, keys):
        "extract selected keys from a dict."
        return dict((k, d[k]) for k in keys if k in d)

    def _now_int(self):
        return int(time.time())

    def get_all_repos(self, installation_id):
        """Get all repos that this installation has access to.

        Useful for testing and debugging.
        """
        url = 'https://api.github.com/installation/repositories'
        headers={'Authorization': f'token {self.get_installation_access_token(installation_id)}',
                 'Accept': 'application/vnd.github+json'}

        response = requests.get(url=url, headers=headers)

        if response.status_code >= 400:
            raise Exception(f'Status code : {response.status_code}, {response.json()}')

        fields = ['name', 'full_name', 'id']
        return [self._extract(x, fields) for x in response.json()['repositories']]


    def generate_installation_curl(self, endpoint):
        iat = self.get_installation_access_token()
        print(f'curl -i -H "Authorization: token {iat}" -H "Accept: application/vnd.github+json" https://api.github.com{endpoint}')

if __name__ == '__main__':

    app_pem = os.getenv('INPUT_APP_PEM')
    app_id = os.getenv('INPUT_APP_ID')

    assert app_pem, 'Must supply input APP_PEM'
    assert app_id, 'Must supply input APP_ID'

    app = GitHubApp(app_pem=app_pem, app_id=app_id)
    id = app.get_installation_id()
    token = app.get_installation_access_token(installation_id=id)
    assert token, 'Token not returned!'

    print(f"::add-mask::{token}")
    print(f"::set-output name=app_token::{token}")
