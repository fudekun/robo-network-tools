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
from flask import current_app, session, make_response


def come_to_me(token_info):  # noqa: E501
    """come_to_me

    # noqa: E501


    :rtype: str
    """
    csrf = flask.request.cookies.get('_ros2.amcl.come_to_me.csrf', None)
    if flask.request.headers.get('Authorization', None) is None:
        raw_taken = session.get('RDBOX_ACCESS_TOKEN', None)
        if raw_taken is not None:
            correct_csrf = session.pop('/ros2/amcl/come_to_me/csrf', None)
            if correct_csrf is None:
                return 'Invalid Request(TimeOut or Unauthorized or Recycled)'
            if correct_csrf != csrf:
                return 'Invalid Request(You need back to /ros2)'
    else:
        raw_taken = flask.request.headers.get('Authorization')[7:]
    if raw_taken is None:
        return 'Invalid token (TimeOut or Unauthorized)'
    jwt_talker = current_app.config['jwt_talker']
    jwt_talker.publish(raw_taken)
    resp = make_response('Success')
    resp.set_cookie('_ros2.amcl.come_to_me.csrf',
                    '',
                    0)
    return resp


def ros2():
    """ros2

    # noqa: E501


    :rtype: str
    """
    csrf = str(uuid.uuid4())
    session['/ros2/amcl/come_to_me/csrf'] = csrf
    resp = make_response(flask.render_template('ros2.html'))
    resp.set_cookie('_ros2.amcl.come_to_me.csrf',
                    csrf,
                    300)
    return resp
