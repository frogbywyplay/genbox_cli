# Copyright (C) 2018 Wyplay, All Rights Reserved.
# This file is part of xbuilder.
#
# xbuilder is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# xbuilder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see file COPYING.
# If not, see <http://www.gnu.org/licenses/>.
#

from setuptools import setup, find_packages

setup(
    name='genbox-cli',
    description='a tool to simplify development with genbox 1.x',
    long_description='''\
this a wrapper to create a docker container ready for genbox 1.x development.
The container will have:
  - a volume for /usr/portage
  - a volume for /usr/targets
  - network=host
  - seccomp profile adapted for the genbox
''',
    version='0.14',
    packages=find_packages(),
    author='PMO',
    author_email='pmo@wyplay.com',
    install_requires=[
        'docker',
        'dockerpty',
        'prompt-toolkit',
    ],
    entry_points={'console_scripts': ['genbox-cli = genbox_cli:main']},
    package_data={'': ['genbox.seccomp.json']}
)
