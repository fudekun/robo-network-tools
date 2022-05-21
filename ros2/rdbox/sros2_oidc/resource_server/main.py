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

import os
import sys

from keycloak import KeycloakOpenID

import rclpy
from rclpy.executors import ExternalShutdownException

from resource_server.jwt_listener import JwtListener

keycloak = KeycloakOpenID(server_url=os.environ['SROS2_OIDC_OP_SERVER_URL'],
                          realm_name=os.environ['SROS2_OIDC_OP_REALM_NAME'],
                          client_id=os.environ['SROS2_OIDC_OP_CLIENT_ID'],
                          client_secret_key=os.environ[
                              'SROS2_OIDC_OP_CLIENT_SECRET_KEY'],
                          verify=False)


def main(args=None):
    rclpy.init(args=args)

    node = JwtListener()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    except ExternalShutdownException:
        sys.exit(1)
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
