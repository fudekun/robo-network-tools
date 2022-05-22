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

"""https://connexion.readthedocs.io/en/latest/security.html detail it."""

from flask import current_app, session, request

import six

from werkzeug.exceptions import Unauthorized


def check_AuthBearer(token):
    """Check auth beare.

    In the case of an illegal token,
    six.raise_from(Unauthorized, e) is sent and a 401.

    :param token: Bearer token string
    :type token: str
    :returns: Dict of jwt clame
    :rtype: dict
    """
    try:
        keycloak = current_app.config['keycloak']
        token_info = keycloak.introspect(token)
    except Exception as e:              # noqa:B902
        six.raise_from(Unauthorized, e)
    if token_info['active'] is False:
        six.raise_from(Unauthorized, Exception)
    return token_info


def check_CookieAuth(api_key, required_scopes):
    if api_key == session.get('RDBOX_SESSIONID', None):
        ret = check_AuthBearer(session['RDBOX_ACCESS_TOKEN'])
    else:
        six.raise_from(Unauthorized, Exception)
    return ret
