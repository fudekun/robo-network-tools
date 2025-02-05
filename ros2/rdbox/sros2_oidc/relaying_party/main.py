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
import random
import string
from datetime import timedelta

import connexion

from keycloak import KeycloakOpenID

import rclpy

from relaying_party import encoder
from relaying_party.jwt_talker import JwtTalker


def main():
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('swagger.yaml',
                arguments={'title': 'sros2_oidc'},
                pythonic_params=True)
    # Session
    password_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(password_characters) for i in range(32))
    app.app.secret_key = password
    app.app.permanent_session_lifetime = timedelta(minutes=3)
    # ROS2
    rclpy.init()
    jwt_talker = JwtTalker()
    # OIDC
    keycloak = KeycloakOpenID(server_url=os.environ[
                                'SROS2_OIDC_OP_SERVER_URL'],
                              realm_name=os.environ[
                                'SROS2_OIDC_OP_REALM_NAME'],
                              client_id=os.environ[
                                'SROS2_OIDC_OP_CLIENT_ID'],
                              client_secret_key=os.environ[
                                'SROS2_OIDC_OP_CLIENT_SECRET_KEY'],
                              verify=False)
    redirect_url = os.environ['SROS2_OIDC_OP_REDIRECT_URL']
    # Save the instances
    app.app.config['jwt_talker'] = jwt_talker
    app.app.config['keycloak'] = keycloak
    app.app.config['redirect_url'] = redirect_url
    # Start this server
    app.run(port=8080, debug=True)
    jwt_talker.destroy_node()
    rclpy.try_shutdown()


if __name__ == '__main__':
    main()
