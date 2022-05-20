# coding: utf-8

from __future__ import absolute_import

from flask import json
from six import BytesIO

from swagger_server.test import BaseTestCase


class TestBaseController(BaseTestCase):
    """BaseController integration test stubs"""

    def test_get_token(self):
        """Test case for get_token

        
        """
        query_string = [('code', 'code_example'),
                        ('session_state', 'session_state_example')]
        response = self.client.open(
            '/gettoken',
            method='GET',
            query_string=query_string)
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_home(self):
        """Test case for home

        
        """
        response = self.client.open(
            '/',
            method='GET')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_login(self):
        """Test case for login

        
        """
        response = self.client.open(
            '/login',
            method='GET')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_logout(self):
        """Test case for logout

        
        """
        response = self.client.open(
            '/logout',
            method='GET')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    import unittest
    unittest.main()
