import sys
from setuptools import setup, find_packages

package_name = 'sros2_oidc'

setup(
    name=package_name,
    version='0.0.1',
    packages=find_packages(),
    package_data={'': ['swagger/swagger.yaml', 'static/*/*.html', 'templates/*.html']},
    include_package_data=True,
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='rdbox-intec',
    maintainer_email='info-rdbox@intec.co.jp',
    description='This is a security tool in ROS2 to securely receive requests from people.',
    license='Apache License 2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'rp = relaying_party.main:main',
            'resource = resource_server.main:main',
        ],
    },
)
