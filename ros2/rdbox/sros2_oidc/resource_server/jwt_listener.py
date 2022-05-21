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
import json
import os
import shutil
import subprocess

from keycloak import KeycloakOpenID

from rclpy.node import Node

from std_msgs.msg import String


class JwtListener(Node):

    def __init__(self):
        super().__init__('jwt_listener')
        self.sub = self.create_subscription(String,
                                            'sros2_oidc',
                                            self.sros2_oidc_callback,
                                            10)
        self.declare_parameter('package_name')
        self.declare_parameter('executable_name')
        self.package_name = self.get_parameter('package_name')\
            .get_parameter_value().string_value
        self.executable_name = self.get_parameter('executable_name')\
            .get_parameter_value().string_value
        self.get_logger().info('Specified conversion module: [ros2 run %s %s]'
                               % (self.package_name, self.executable_name))
        self.keycloak = KeycloakOpenID(server_url=os.environ[
                                           'SROS2_OIDC_OP_SERVER_URL'],
                                       realm_name=os.environ[
                                           'SROS2_OIDC_OP_REALM_NAME'],
                                       client_id=os.environ[
                                           'SROS2_OIDC_OP_CLIENT_ID'],
                                       client_secret_key=os.environ[
                                           'SROS2_OIDC_OP_CLIENT_SECRET_KEY'],
                                       verify=False)

    def sros2_oidc_callback(self, msg):
        try:
            userinfo = self.keycloak.introspect(msg.data)
            if userinfo['active'] is False:
                raise ValueError('token_info.active is false')
        except ValueError as e:
            raise ValueError(e)
        except Exception as e:      # noqa:B902
            raise e
        raw_json = json.dumps(userinfo)
        param = "info:='{}'".format(raw_json)
        ros2_path = shutil.which('ros2')
        if ros2_path is None:
            raise AttributeError('a path of ros2 not found')
        env = os.environ.copy()
        env['ROS_SECURITY_ENABLE'] = 'false'
        subprocess.Popen([ros2_path,
                          'run',
                          self.package_name,
                          self.executable_name,
                          '--ros-args',
                          '-p', param],
                         env=env)
