# Copyright 2022 Intec Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid

import flask
from flask import current_app, session

import six

from werkzeug.exceptions import Forbidden


def get_token(code=None, session_state=None, state=None):  # noqa: E501
    """get_token

     # noqa: E501

    :param code: 
    :type code: str
    :param session_state: 
    :type session_state: str
    :param state: 
    :type state: str

    :rtype: str
    """
    if state == session['state']:
        six.raise_from(Forbidden)
    else:
        session.pop('state')
    keycloak = current_app.config['keycloak']
    redirect_url = current_app.config['redirect_url']
    raw_token = keycloak.token(code=code,
                               grant_type='authorization_code',
                               redirect_uri=redirect_url)
    # Verify the TOKEN
    KEYCLOAK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\n'
    KEYCLOAK_PUBLIC_KEY += keycloak.public_key()
    KEYCLOAK_PUBLIC_KEY += '\n-----END PUBLIC KEY-----'
    options = {'verify_signature': True,
               'verify_aud': True,
               'verify_exp': True}
    keycloak.decode_token(raw_token['access_token'],
                          key=KEYCLOAK_PUBLIC_KEY,
                          options=options)
    unique_key = str(uuid.uuid4())
    session['RDBOX_SESSIONID'] = unique_key
    session['RDBOX_ACCESS_TOKEN'] = raw_token['access_token']
    session['RDBOX_REFRESH_TOKEN'] = raw_token['refresh_token']
    # Redirect Success page
    resp = flask.redirect('/ros2', code=302)
    resp.set_cookie('RDBOX_SESSIONID',
                    unique_key,
                    int(raw_token['refresh_expires_in']))
    return resp


def home():  # noqa: E501
    """home

    # noqa: E501


    :rtype: str
    """
    return flask.send_from_directory('./static/home', 'index.html')


def login():  # noqa: E501
    """login

    # noqa: E501


    :rtype: str
    """
    keycloak = current_app.config['keycloak']
    redirect_url = current_app.config['redirect_url']
    state = uuid.uuid4()
    session['state'] = state
    url = keycloak.auth_url(redirect_url)
    url += '&state={}'.format(state)
    return flask.redirect(url, code=302)


def logout():  # noqa: E501
    """logout

    # noqa: E501


    :rtype: str
    """
    if flask.request.headers.get('Authorization', None) is None:
        refresh_token = session.get('RDBOX_REFRESH_TOKEN', None)
    else:
        refresh_token = flask.request.headers.get('Authorization')[7:]
    keycloak = current_app.config['keycloak']
    if refresh_token is not None:
        keycloak.logout(refresh_token)
    session.clear()
    resp = flask.redirect('/', code=302)
    resp.set_cookie('RDBOX_SESSIONID',
                    '',
                    0)
    return resp
