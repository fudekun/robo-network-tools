import imp
import connexion
import six
import flask
from relaying_party import util


def come_to_me(token_info):  # noqa: E501
    """come_to_me

    # noqa: E501


    :rtype: str
    """
    from relaying_party.main import jwt_talker
    raw_taken = flask.request.headers.get('Authorization')[7:]
    jwt_talker.publish(raw_taken)
    return 'do some magic!'
