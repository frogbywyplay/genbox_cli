# Copyright (C) 2018-2019 Wyplay, All Rights Reserved.
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

import requests


class Reg:
    def __init__(self, url, creds):
        if not url.startswith('http'):
            url = 'https://{}'.format(url)
        self.base_url = url
        self.s = requests.Session()
        self.s.auth = creds

    def _url(self, path):
        return '{}/v2/{}'.format(self.base_url, path)

    def get(self, path, **kwargs):
        reply = self.s.get(self._url(path), **kwargs)
        reply.raise_for_status()
        return reply

    def ls(self, repo):
        tags = self.get('{}/tags/list'.format(repo)).json()['tags']
        if tags:
            for tag in tags:
                yield '{}:{}'.format(repo, tag)
        else:
            yield repo


class HubApi:
    def __init__(self):
        self.base_url = 'https://hub.docker.com'
        self.s = requests.Session()

    def _url(self, path):
        return '{}/v2/repositories/{}'.format(self.base_url, path)

    def get(self, url, **kwargs):
        reply = self.s.get(url, **kwargs)
        reply.raise_for_status()
        return reply

    def ls(self, repo):
        url = self._url('{}/tags'.format(repo))
        while True:
            reply = self.get(url).json()
            for tag in reply['results']:
                yield '{}:{}'.format(repo, tag['name'])
            url = reply['next']
            if not url:
                break
