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

import flask
from flask import current_app


def get_token(code=None, session_state=None):  # noqa: E501
    """get_token

     # noqa: E501

    :param code: 
    :type code: str
    :param session_state: 
    :type session_state: str

    :rtype: str
    """
    keycloak = current_app.config['keycloak']
    redirect_url = current_app.config['redirect_url']
    raw_token = keycloak.token(code=code,
                               grant_type='authorization_code',
                               redirect_uri=redirect_url)
    resp = flask.send_from_directory('static/ros2', 'index.html')
    resp.set_cookie('RDBOX_ACCESS_TOKEN',
                    raw_token['access_token'],
                    int(raw_token['expires_in']))
    resp.set_cookie('RDBOX_REFRESH_TOKEN',
                    raw_token['refresh_token'],
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
    url = keycloak.auth_url(redirect_url)
    return flask.redirect(url, code=302)


def logout():  # noqa: E501
    """logout

    # noqa: E501


    :rtype: str
    """
    keycloak = current_app.config['keycloak']
    refresh_token = flask.request.headers.get('Authorization')
    keycloak.logout(refresh_token[7:])
    return flask.redirect('/', code=302)
