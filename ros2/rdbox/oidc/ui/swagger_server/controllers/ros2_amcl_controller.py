import connexion
import six

from swagger_server import util


def come_to_me(token_info):  # noqa: E501
    """come_to_me

    # noqa: E501


    :rtype: str
    """
    # TODO: Support ROS2 Command from token info(token_info['location'])
    print(token_info['location'])
    return 'do some magic!'
