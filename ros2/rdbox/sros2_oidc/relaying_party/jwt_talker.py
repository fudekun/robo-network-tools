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


import string
from rclpy.node import Node

from std_msgs.msg import String


class JwtTalker(Node):

    def __init__(self):
        super().__init__('jwt_talker')
        self.pub = self.create_publisher(String, 'sros2_oidc', 10)

    def publish(self, jwt: str):
        msg = String()
        msg.data = jwt
        self.pub.publish(msg)
