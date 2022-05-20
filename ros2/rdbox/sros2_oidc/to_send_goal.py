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


import rclpy
from rclpy.node import Node

from geometry_msgs.msg import PoseStamped


class Talker(Node):

    def __init__(self):
        super().__init__('talker')
        self.pub = self.create_publisher(PoseStamped, '/goal_pose', 10)

    def publish(self):
        pose = PoseStamped()
        pose.pose.position.x = 3.0
        pose.pose.position.y = 2.3
        pose.pose.position.z = 0.0
        self.pub.publish(pose)


def main(args=None):
    rclpy.init(args=args)
    node = Talker()
    node.publish()

if __name__ == '__main__':
    main()
