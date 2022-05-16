# coding: utf-8

from __future__ import absolute_import

from flask import json
from six import BytesIO

from swagger_server.test import BaseTestCase


class TestRos2AmclController(BaseTestCase):
    """Ros2AmclController integration test stubs"""

    def test_come_to_me(self):
        """Test case for come_to_me

        
        """
        response = self.client.open(
            '/ros2/amcl/come_to_me',
            method='GET')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    import unittest
    unittest.main()
