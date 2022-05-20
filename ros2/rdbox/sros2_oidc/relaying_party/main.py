#!/usr/bin/env python3

import connexion

from keycloak import KeycloakOpenID

import rclpy

from relaying_party import encoder
from relaying_party.jwt_talker import JwtTalker


jwt_talker = None

keycloak = KeycloakOpenID(server_url="https://keycloak.rdbox.172-16-0-132.nip.io/auth/",
                          realm_name="ros2_oidc",
                          client_id="amcl",
                          client_secret_key="********************",
                          verify=False)
redirect_url = 'http://rdbox.172-16-0-132.nip.io:8080/gettoken'


def main():
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('swagger.yaml',
                arguments={'title': 'sros2_oidc'},
                pythonic_params=True)
    rclpy.init()
    global jwt_talker
    if jwt_talker is None:
        jwt_talker = JwtTalker()
    app.run(port=8080)


if __name__ == '__main__':
    main()
