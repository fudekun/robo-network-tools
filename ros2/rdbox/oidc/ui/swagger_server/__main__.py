#!/usr/bin/env python3

import connexion
from keycloak import KeycloakOpenID
from swagger_server import encoder

keycloak = KeycloakOpenID(server_url="https://keycloak.rdbox.172-16-0-110.nip.io/auth/",
                          realm_name="rdbox",
                          client_id="ros2",
                          client_secret_key="dZoR9DkaxorF0LPKoEjWdb34vJbiQkCS",
                          verify=False)


def main():
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('swagger.yaml', arguments={'title': 'ros2_oidc'}, pythonic_params=True)
    app.run(port=8080, debug=True)


if __name__ == '__main__':
    main()
