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
import sys

from geometry_msgs.msg import PoseStamped

import rclpy


def main(args=None):
    rclpy.init(args=args)
    node = rclpy.create_node('talker_goal_pose')
    node.declare_parameter('info', '{}')
    token_info = node.get_parameter('info')\
        .get_parameter_value().string_value
    pub = node.create_publisher(PoseStamped, 'goal_pose', 10)
    try:
        token_dict = json.loads(token_info)
    except Exception as e:     # noqa:B902
        raise e
    if 'location' not in token_dict:
        raise KeyError('location not in token_info')
    raw_location = token_dict['location']
    x_pos, y_pos = [float(val) for val in raw_location.split(',')]
    pose = PoseStamped()
    pose.pose.position.x = x_pos
    pose.pose.position.y = y_pos
    pose.pose.position.z = 0.0
    pub.publish(pose)
    node.get_logger().info('Accept: [%s]' % raw_location)
    rclpy.shutdown()


if __name__ == '__main__':
    main(token_info=sys.argv[1])
