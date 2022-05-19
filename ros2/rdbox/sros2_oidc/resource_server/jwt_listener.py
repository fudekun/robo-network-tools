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
from geometry_msgs.msg import PoseStamped

from keycloak import KeycloakOpenID

from rclpy.node import Node

from std_msgs.msg import String


keycloak = KeycloakOpenID(server_url="https://keycloak.rdbox.172-16-0-132.nip.io/auth/",
                          realm_name="ros2_oidc",
                          client_id="amcl",
                          client_secret_key="fkRX4Vb2DdUa1A6tWttQFQawnfv8teNF",
                          verify=False)


class JwtListener(Node):

    def __init__(self):
        super().__init__('jwt_listener')
        self.sub = self.create_subscription(String,
                                            'sros2_oidc',
                                            self.sros2_oidc_callback,
                                            10)
        self.pub = self.create_publisher(PoseStamped, 'goal_pose', 10)

    def sros2_oidc_callback(self, msg):
        try:
            token_info = keycloak.introspect(msg.data)
            if token_info['active'] is False:
                raise Exception
        except Exception:
            raise Exception
        raw_location = token_info['location']
        x_pos, y_pos = [float(val) for val in raw_location.split(',')]
        pose = PoseStamped()
        pose.pose.position.x = x_pos
        pose.pose.position.y = y_pos
        pose.pose.position.z = 0.0
        self.pub.publish(pose)
        self.get_logger().info('Accept: [%s]' % raw_location)
