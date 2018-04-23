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

fmt:
	pipenv run unify -ir setup.py genbox_cli
	pipenv run yapf -ir setup.py genbox_cli

pyflakes:
	pipenv run pyflakes setup.py genbox_cli

pylint:
	pipenv run pylint setup.py genbox_cli

deb:
	rm -rf deb_dist
	pipenv run python setup.py --command-packages=stdeb.command bdist_deb
