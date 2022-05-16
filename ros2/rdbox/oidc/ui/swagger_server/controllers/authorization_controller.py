from swagger_server.__main__ import keycloak
from werkzeug.exceptions import Unauthorized
import six

"""
controller generated to handled auth operation described at:
https://connexion.readthedocs.io/en/latest/security.html
"""


def check_AuthBearer(token):
    try:
        token_info = keycloak.introspect(token)
        if token_info['active'] is False:
            six.raise_from(Unauthorized, Exception)
    except Exception as e:
        six.raise_from(Unauthorized, e)
    return token_info
