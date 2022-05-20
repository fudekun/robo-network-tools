import flask
from relaying_party.main import keycloak, redirect_url


def get_token(code=None, session_state=None):  # noqa: E501
    """get_token

     # noqa: E501

    :param code: 
    :type code: str
    :param session_state: 
    :type session_state: str

    :rtype: str
    """
    raw_token = keycloak.token(code=code, grant_type='authorization_code', redirect_uri=redirect_url)
    resp = flask.send_from_directory('static/ros2', 'index.html')
    # resp.headers['Authorization'] = 'Bearer {}'.format(raw_token['access_token'])
    resp.set_cookie('RDBOX_ACCESS_TOKEN', raw_token['access_token'], int(raw_token['expires_in']))
    resp.set_cookie('RDBOX_REFRESH_TOKEN', raw_token['refresh_token'], int(raw_token['refresh_expires_in']))
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
    url = keycloak.auth_url(redirect_url)
    return flask.redirect(url, code=302)


def logout():  # noqa: E501
    """logout

    # noqa: E501


    :rtype: str
    """
    refresh_token = flask.request.headers.get('Authorization')
    keycloak.logout(refresh_token[7:])
    return flask.redirect('/', code=302)
