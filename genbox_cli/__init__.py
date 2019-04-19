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

import argparse
import configparser
import copy
import functools
import getpass
import io
import itertools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

import requests

import docker

from prompt_toolkit import prompt

from dockerpty.pty import PseudoTerminal, ExecOperation  # pylint: disable=no-name-in-module

from genbox_cli import docker_catalog

__version__ = '0.15'

# logging facility

VLEVELS = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}


class ColoredConsoleHandler(logging.StreamHandler):
    def emit(self, record):
        # Need to make a actual copy of the record
        # to prevent altering the message for other loggers
        myrecord = copy.copy(record)
        levelno = myrecord.levelno
        if levelno >= 50:  # CRITICAL / FATAL
            color = '\x1b[31m'  # red
        elif levelno >= 40:  # ERROR
            color = '\x1b[31m'  # red
        elif levelno >= 30:  # WARNING
            color = '\x1b[33m'  # yellow
        elif levelno >= 20:  # INFO
            color = '\x1b[32m'  # green
        elif levelno >= 10:  # DEBUG
            color = '\x1b[35m'  # pink
        else:  # NOTSET and anything else
            color = '\x1b[0m'  # normal
        myrecord.msg = color + str(myrecord.msg) + '\x1b[0m'  # normal
        logging.StreamHandler.emit(self, myrecord)


def init_logging(vlevel):
    """ init logger with 2 handlers:
        one file handler in /var/log/genbox/genbox-cli.log with DEBUG level
        one stderr handler
    """
    root = logging.getLogger()
    root.setLevel(VLEVELS.get(vlevel, logging.DEBUG))

    shdlr = ColoredConsoleHandler()
    shdlr.setFormatter(logging.Formatter('%(message)s'))
    root.addHandler(shdlr)

    fhdlr = logging.FileHandler('/var/log/genbox-cli.{}.log'.format(getpass.getuser()))
    fhdlr.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
    fhdlr.setLevel(logging.DEBUG)
    root.addHandler(fhdlr)

    ui = logging.getLogger('gbx.ui')
    ui.propagate = False
    ui.addHandler(fhdlr)


def printlog(*args, **kwargs):
    print(*args, **kwargs)
    logging.getLogger('gbx.ui').info(' '.join(args))


# docker helpers


def pull(cli, iname):
    printlog('Checking whether the image is already present locally... ', end='')
    try:
        img = cli.images.get(iname)
        printlog('yes.')
        logging.info('Image %s is present.', iname)
        version = iname.split(':')[1] if ':' in iname else 'latest'
        if version == 'latest':
            printlog('Version is latest: Pull needed.')
        else:
            printlog('Version is {}. No pull needed.'.format(iname))
            return img
    except docker.errors.ImageNotFound:
        printlog('no. Pull needed.')

    printlog('Pulling {}'.format(iname))
    try:
        for out in cli.api.pull(iname, stream=True):
            data = json.loads(out.decode('utf-8'))
            status = data['status']
            if status in ['Downloading', 'Extracting']:
                printlog(status, data['progress'], end='\r')
            else:
                printlog(status)
    except docker.errors.NotFound as e:
        logging.error(e.explanation)
        return None
    printlog('Image {} pulled'.format(iname))
    return cli.images.get(iname)


def creds_from_config(registry):
    authconfig = docker.auth.resolve_authconfig(docker.auth.load_config(), registry)
    if not authconfig:
        return None
    # sometimes key is "Username" sometimes "username"...
    authconfig = dict((k.lower(), v) for k, v in authconfig.items())
    try:
        return tuple(authconfig[k] for k in ['username', 'password'])
    except KeyError:
        return None


def mk_addfile_args(fname, fl):
    tinfo = tarfile.TarInfo(fname)
    try:
        tinfo.size = os.path.getsize(fl.name)
    except AttributeError:
        tinfo.size = len(fl.getvalue())
    return tinfo, fl


# https://github.com/docker/compose/blob/master/compose/config/config.py
def split_path_mapping(volume_config):
    if ':' in volume_config:
        host, container_path = volume_config.split(':', 1)
        if ':' in container_path:
            container_path, mode = container_path.rsplit(':', 1)
        else:
            mode = 'rw'

        return host, dict(bind=container_path, mode=mode)
    else:
        return volume_config, None


def dict_from_path_mappings(path_mappings):
    if not path_mappings:
        return {}
    return dict(split_path_mapping(v) for v in path_mappings)


class PwdFile(object):
    def __init__(self, content):
        self.pwd = list(self.parse(content))

    @staticmethod
    def parse(content):
        for line in content.split('\n'):
            if not line:
                continue
            toks = line.split(':')
            yield toks[0], int(toks[2]), int(toks[3])

    def by_uid(self, uid):
        try:
            return next(l for l in self.pwd if l[1] == uid)
        except StopIteration:
            raise KeyError(uid)

    def by_name(self, name):
        try:
            return next(l for l in self.pwd if l[0] == name)
        except StopIteration:
            raise KeyError(name)


class GenboxContainer(object):
    def __init__(self, cli, name):
        self.cli = cli
        self.cont = cli.containers.get('gbx-{}-genbox'.format(name))

    def reloaded(self):
        self.cont.reload()
        return self.cont

    @property
    def _mounts(self):
        return self.cont.attrs['Mounts']

    def _mount(self, dest):
        for m in self._mounts:
            if m['Destination'] == dest:
                yield m['Name']

    def usr_targets(self):
        return next(self._mount('/usr/targets'), '')

    def usr_portage(self):
        return next(self._mount('/usr/portage'))

    def put_files(self, files):
        """
            files is a dict src => dest
        """
        with io.BytesIO() as fileobj:
            with tarfile.open(mode='w', fileobj=fileobj) as tar:
                for dest, fl in files:
                    tar.addfile(*mk_addfile_args(dest, fl))
            self.cont.put_archive('/', fileobj.getvalue())

    def get_file(self, path):
        """
            files is a dict src => dest

            raise docker.errors.NotFount
        """
        return self.cont.get_archive(path)[0]

    def start(self):
        cont = self.cont
        while True:
            cont.start()
            time.sleep(1)
            cont.reload()
            if cont.status == 'running':
                break
        return self

    def attach(self, usermode):
        self.exec_run(['bash', '-l'], usermode)

    def exec_run(self, cmd, usermode=None, **kwargs):
        if usermode:
            kwargs.update(user=str(os.getuid()))

        exec_id = self.cli.api.exec_create(
            self.cont.id,
            cmd,
            stdout=True,
            stderr=True,
            stdin=True,
            tty=True,
            environment=dict(SSH_AUTH_SOCK=os.getenv('SSH_AUTH_SOCK')),
            **kwargs
        )
        operation = ExecOperation(self.cli.api, exec_id, interactive=True)
        pty = PseudoTerminal(self.cli.api, operation)
        pty.start()

    def setup(self, email, name, username, force=False):
        ctx = context()
        prev = ctx.setdefault('genbox', dict()).setdefault(self.cont.name, dict())
        gbx_config_done = prev.setdefault('genbox-config-done', False)
        if not gbx_config_done:
            logging.info('I will run genbox-config')
            self.exec_run('genbox-config')
        prev['genbox-config-done'] = True
        update_context(ctx)
        return self

    def setup_usermode(self, user, username):
        if not user:
            return self

        passwd_gz = self.get_file('/etc/passwd')
        try:
            s = io.BytesIO(passwd_gz.read())
        except AttributeError:
            # py3.5: passwd_gz is generator object APIClient._stream_raw_result and has no read method
            s = io.BytesIO(b''.join(passwd_gz))
        with tarfile.open(fileobj=s) as t:
            content = t.extractfile('passwd').read().decode()
        pwd = PwdFile(content)
        uid = os.getuid()

        try:
            pwd.by_uid(uid)
            # uid exist, ok
            logging.debug('User %s already exist', uid)
            return self
        except KeyError:
            pass

        while True:
            try:
                pwd.by_name(username)
                # user 'username' already exists, but not with the request uid
                logging.debug('User %s already exist, but not with %s uid', username, uid)
                username += '0'
            except KeyError:
                break

        logging.info('adding user %s with uid %s', username, uid)
        logging.debug(self.cont.exec_run(['useradd', username, '-G', 'wheel,portage', '-o', '-u', str(uid)]))

        return self

    # cleanup
    def cleanup(self, volumes, force):
        if not force:
            printlog('This will destroy the container and all associated volumes')
            resp = prompt('Are you sure [Yn] ?').strip().lower()
            if not resp or resp[0] != 'y':
                printlog('Cancelled.')
                return
        printlog("Removing genbox and it's volumes")
        self.cont.remove(v=volumes, force=True)


class GenboxContainerLow(object):
    """
        low level genbox creation helpers (volumes & container)
    """

    def __init__(self, cli, name):
        self.cli = cli
        self.name = name

    # /usr/portage

    def get_existing_portage(self, share_portage):
        try:
            return GenboxContainer(self.cli, share_portage).usr_portage()
        except docker.errors.NotFound:
            pass
        try:
            return self.cli.volumes.get(share_portage).name
        except docker.errors.NotFound:
            pass
        logging.error('Could not find volume for %s', share_portage)

    def create_portage(self, img, vers):
        vname = 'gbx-{}-portage-{}'.format(self.name, int(time.time()))
        try:
            printlog('Using volume {} for {}'.format(vname, self.name))
            return self.cli.volumes.get(vname).name
        except docker.errors.NotFound:
            pass
        printlog('Creating portage volume for {}'.format(self.name))
        vol = self.cli.volumes.create(vname)
        printlog('Initialize portage volume for {}'.format(self.name))
        iname = '{}:{}'.format(img, vers)
        if pull(self.cli, iname) is None:
            return None
        logging.info('docker run -v %s:/usr/portage %s', vol.name, iname)
        cont = self.cli.containers.create(
            image=iname,
            volumes={
                vol.name: dict(
                    bind='/usr/portage',
                    mode='rw',
                ),
            },
        )
        cont.remove()
        printlog('portage volume for {} initialized'.format(self.name))
        return vol.name

    def get_portage(self, portage_image, portage_version, share_portage):
        if share_portage:
            pvol = self.get_existing_portage(share_portage)
        else:
            pvol = self.create_portage(portage_image, portage_version)
        return pvol

    # /usr/targets

    def get_existing_targets(self, share_targets):
        try:
            return GenboxContainer(self.cli, share_targets).usr_targets()
        except docker.errors.NotFound:
            pass
        try:
            return self.cli.volumes.get(share_targets).name
        except docker.errors.NotFound:
            pass
        logging.error('Could not find volume for %s', share_targets)

    def create_targets(self):
        vname = 'gbx-{}-targets-{}'.format(self.name, int(time.time()))
        try:
            return self.cli.volumes.get(vname).name
        except docker.errors.NotFound:
            pass
        printlog('Creating targets volume for {}'.format(self.name))
        return self.cli.volumes.create(vname).name

    def get_targets(self, share_targets):
        if share_targets:
            pvol = self.get_existing_targets(share_targets)
        else:
            pvol = self.create_targets()
        return pvol

    # genbox proper
    def get_genbox(self):
        cname = 'gbx-{}-genbox'.format(self.name)
        try:
            self.cli.containers.get(cname)
            printlog('genbox container for {} already exist'.format(self.name))
            return True
        except docker.errors.NotFound:
            pass

    def create_genbox(self, iname, vname, tname, privileged, volumes, user, usermode):  # pylint: disable=too-many-arguments, too-many-locals
        cname = 'gbx-{}-genbox'.format(self.name)
        try:
            self.cli.containers.get(cname)
            printlog('genbox container for {} already exist'.format(self.name))
            return False
        except docker.errors.NotFound:
            pass
        ctx = context()
        try:
            del ctx.setdefault('genbox', dict())[cname]
        except KeyError:
            pass
        update_context(ctx)

        if pull(self.cli, iname) is None:
            return None
        logging.info('Creating genbox container for %s', self.name)

        dvolumes = {
            vname: {
                'bind': '/usr/portage',
                'mode': 'rw'
            },
            '/tmp': {
                'bind': '/tmp',
                'mode': 'rw'
            },
        }
        if os.getenv('SSH_AUTH_SOCK'):
            ssh_sock_dir = os.path.dirname(os.getenv('SSH_AUTH_SOCK'))
            if not ssh_sock_dir.startswith(
                '/tmp'
            ):  # /tmp is already mount/bind so do not rebind one of its subdirectory
                dvolumes[ssh_sock_dir] = {'bind': ssh_sock_dir, 'mode': 'rw'}
        else:
            logging.warning('No SSH_AUTH_SOCK defined => You will have troubles to correctly setup the genbox.')
        if tname:
            dvolumes[tname] = {'bind': '/usr/targets', 'mode': 'rw'}
        dvolumes.update(dict_from_path_mappings(volumes))
        if usermode:
            home = os.path.expanduser('~')
            dvolumes.setdefault(home, dict(bind=os.path.join('/home', user), mode='rw'))

        with open(os.path.join(os.path.dirname(__file__), 'genbox.seccomp.json')) as fl:
            seccomp_profile = fl.read()
        logging.info(
            'docker run -d --name %s '  # container name
            '%s '  # volumes
            '--restart=always %s '  # privileged
            '-e SSH_AUTH_SOCK=%s '  # SSH_AUTH_SOCK
            '--init --security-opt seccomp=%s '  # path to seccomp spec file
            '--network=host %s '  # image name
            'tail -f /dev/null',
            iname,
            ' '.join('-v {}:{}'.format(k, v['bind']) for k, v in dvolumes.items()),
            '-p' if privileged else '',
            os.getenv('SSH_AUTH_SOCK'),
            os.path.join(os.path.dirname(__file__), 'genbox.seccomp.json'),
            iname
        )
        self.cli.containers.create(
            iname,
            command='tail -f /dev/null',
            name=cname,
            hostname=self.name,
            volumes=dvolumes,
            restart_policy=dict(Name='always'),
            privileged=privileged,
            environment=dict(SSH_AUTH_SOCK=os.getenv('SSH_AUTH_SOCK')),
            init=True,
            labels={
                'genbox': 'true',
                'genbox.name': self.name,
            },
            security_opt=[
                # run x86 binaries on a amd64 (personality syscall)
                'seccomp={}'.format(seccomp_profile)
            ],
            # simplify networking for webapp & co
            network='host',
        )
        return True


def split_image(image):
    toks = image.split('/', 1)
    if '.' not in toks[0]:
        return None, image
    return toks[0], toks[1]


def get_registry(url):
    if not url:
        return docker_catalog.HubApi()
    return docker_catalog.Reg(url, creds_from_config(url))


class App(object):
    """
    implements command-line commands: enter, ls, ...
    """

    @staticmethod
    def enter(cfg):
        cli = cfg.cli
        name = cfg.name
        gbxlow = GenboxContainerLow(cli, name)
        if not gbxlow.get_genbox():
            pvol = gbxlow.get_portage(cfg.portage_image, cfg.portage_version, cfg.share_portage)
            logging.debug('portage volume will be %s', pvol)
            if not pvol:
                return
            if cfg.no_targets_volume:
                tvol = None
            else:
                tvol = gbxlow.get_targets(cfg.share_targets)
                logging.debug('targets volume will be %s', tvol)
                if not tvol:
                    return
            force = gbxlow.create_genbox(
                '{}:{}'.format(cfg.image, cfg.version), pvol, tvol, cfg.privileged, cfg.volume, cfg.user_username,
                cfg.user_mode
            )
            if force is None:
                return
        else:
            force = False
        gbx = (
            GenboxContainer(cli, name).start().setup(cfg.user_name, cfg.user_email, cfg.user_username, force)
            .setup_usermode(cfg.user_mode, cfg.user_username)
        )
        if not cfg.no_attach:
            gbx.attach(cfg.user_mode)

    @staticmethod
    def exec(cfg):
        try:
            GenboxContainer(cfg.cli, cfg.name).start().exec_run(cfg.cmd, cfg.user_mode)
        except docker.errors.NotFound:
            logging.error('Cound not find genbox %s', cfg.name)
            return

    @staticmethod
    def setup(cfg):
        try:
            gbx = GenboxContainer(cfg.cli, cfg.name)
        except docker.errors.NotFound:
            logging.error('Cound not find genbox %s', cfg.name)
            return
        gbx.setup(cfg.user_name, cfg.user_email, cfg.user_username, cfg.force)

    @staticmethod
    def rm(cfg):
        try:
            gbx = GenboxContainer(cfg.cli, cfg.name)
        except docker.errors.NotFound:
            logging.error('Cound not find genbox %s', cfg.name)
            return
        gbx.cleanup(cfg.clean_volumes, cfg.force)

    @staticmethod
    def available(cfg):
        url, rrepo = split_image(cfg.image)
        reg = get_registry(url)
        try:
            for tag in sorted(s for s in reg.ls(rrepo)):
                printlog(tag)
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code:
                logging.error('You do not have access to %s', reg)
                logging.error('Please login first with docker login')
            else:
                raise

    @staticmethod
    def ls(cfg):
        portage_vols = set()
        targets_vols = set()
        printlog('Installed genboxes')
        for container in cfg.cli.containers.list(all=True):
            m = re.match(r'gbx-(.+)-genbox', container.name)
            if m:
                name = m.group(1)
                gbx = GenboxContainer(cfg.cli, name)
                portage_vol = gbx.usr_portage()
                target_vol = gbx.usr_targets()
                portage_vols.add(portage_vol)
                targets_vols.add(target_vol)
                printlog(name, gbx.cont.attrs['State']['Status'], portage_vol, target_vol)
        if not cfg.orphans:
            return
        printlog()
        printlog('Orphaned portage volumes')
        for volume in cfg.cli.volumes.list():
            vname = volume.name
            if re.match(r'gbx-.+-portage', vname):
                printlog(vname)
        printlog()
        printlog('Orphase targets volumes')
        for volume in cfg.cli.volumes.list():
            vname = volume.name
            if re.match(r'gbx-.+-targets', vname):
                printlog(vname)


# TODO: move this inside the genbox or labels
def context():
    contextdir = os.path.expanduser('~/.config')
    os.makedirs(contextdir, exist_ok=True)
    contextjson = os.path.join(contextdir, 'genbox-cli.json')
    try:
        with open(contextjson) as fl:
            return json.load(fl)
    except FileNotFoundError:
        return {}


def update_context(new_context):
    contextdir = os.path.expanduser('~/.config')
    os.makedirs(contextdir, exist_ok=True)
    contextjson = os.path.join(contextdir, 'genbox-cli.json')
    with open(contextjson, 'w') as fl:
        return json.dump(new_context, fl)


class MergeConfig(object):
    """
        mix config options from cli and ~/.genboxrc
    """

    def __init__(self, args):
        self.args = args
        cp = configparser.RawConfigParser()
        cp.read(os.path.expanduser(args.config))
        self.cp = cp

    CLI_DEFAULTS = dict(
        image='docker.wyplay.com/tools/genbox',
        version='latest',
        portage_image='docker.wyplay.com/tools/genbox-portage'
    )

    @property
    def cli(self):
        return docker.from_env(timeout=60 * 10)

    @property
    def user_name(self):
        return self.cp.get('user', 'name')

    @property
    def user_email(self):
        return self.cp.get('user', 'email')

    @property
    def user_username(self):
        try:
            return self.cp.get('user', 'username')
        except (configparser.NoSectionError, configparser.NoOptionError):
            return getpass.getuser()

    @property
    def volume(self):
        return set(
            itertools.chain(
                (v for v in self.cp.get('container', 'volumes', fallback='').split(' ') if v),
                self.args.volume,
            )
        )

    @property
    def clean_volumes(self):
        return self.args.volumes

    @property
    def image(self):
        return self.cascade('container', 'image')

    @property
    def version(self):
        return self.cascade('container', 'version')

    @property
    def portage_image(self):
        return self.cascade('container', 'portage_image')

    @property
    def portage_version(self):
        try:
            return self.cascade('container', 'portage_version')
        except AttributeError:
            return self.version

    @property
    def cmd(self):
        cmd = self.args.cmd
        if not cmd:
            return ['bash', '-l']
        if cmd[0] == '--':
            cmd.pop(0)
        if not cmd:
            return ['bash', '-l']
        return cmd

    def cascade(self, section, name):
        try:
            # retrieve value from cmdline
            value = getattr(self.args, name)
            if value:
                return value
        except AttributeError:
            pass
        try:
            # not found in cmdline, try ~/.genboxrc
            return self.cp.get(section, name)
        except (configparser.NoSectionError, configparser.NoOptionError):
            pass
        try:
            # not found in cmdline, then ~/.genboxrc, try default values
            return self.CLI_DEFAULTS[name]
        except KeyError:
            pass
        raise AttributeError(name)

    def __getattr__(self, name):
        return getattr(self.args, name)


class SanityCheck(object):
    @staticmethod
    def pre_check():
        user = getpass.getuser()
        if os.access('/var/log/genbox-cli.{}.log'.format(user), os.W_OK):
            return
        print(
            '''\
It seems that /var/log/genbox-cli.{user}.log folder is not writeable.
I will create it with:
$ sudo touch /var/log/genbox-cli.{user}.log && sudo chown {user}:{user} /var/log/genbox-cli.{user}.log
'''.format(user=user)
        )
        p = subprocess.Popen(['sudo', 'touch', '/var/log/genbox-cli.{}.log'.format(user)])
        out, err = p.communicate()
        if p.returncode:
            logging.error('Something went wrong :\n%s\n%s\n', out, err)
        p = subprocess.Popen([
            'sudo', 'chown', '{}:{}'.format(os.getuid(), os.getgid()), '/var/log/genbox-cli.{}.log'.format(user)
        ])
        out, err = p.communicate()
        if p.returncode:
            logging.error('Something went wrong :\n%s\n%s\n', out, err)

    def check(self, cfg):
        for chk in [
            functools.partial(self.check_dockerd_is_running, cfg),
            self.check_docker_sock,
            functools.partial(self.check_cfg, cfg),
        ]:
            if chk():
                return True
        return None

    @staticmethod
    def check_dockerd_is_running(cfg):
        cli = cfg.cli

        try:
            cli.version()
        except requests.exceptions.ConnectionError:
            logging.error('Dockerd in not running')
            if not shutil.which('dockerd'):
                logging.error('Please install docker and start it:')
                logging.error('You can find the install documentation here: https://docs.docker.com/install/')
                logging.error('Then start it:')
            else:
                logging.error('Start the Docker daemon:')
            logging.error('$ sudo systemctl enable docker')
            logging.error('$ sudo systemctl start docker')
            return True
        return None

    @staticmethod
    def check_docker_sock():
        if os.access('/var/run/docker.sock', os.W_OK):
            return None
        logging.error('You do not have access to docker control socket:')
        logging.error('/var/run/docker.sock')
        logging.error('Add you user to the group docker:')
        logging.error('$ sudo usermod -a -G docker $USER')
        logging.error('or run genbox-cli command with sudo')
        return True

    @staticmethod
    def check_cfg(cfg):
        err = None
        if cfg.cp.get('user', 'name', fallback=None) is None:
            logging.error('Please add [user].name to %s', cfg.config)
            err = True
        if cfg.cp.get('user', 'email', fallback=None) is None:
            logging.error('Please add [user].email to %s', cfg.config)
            err = True
        if err:
            logging.error('see https://tools.wyplay.com/genbox-cli#configuration')
        return err

    @staticmethod
    def check_agent():
        rc = subprocess.call(['ssh-add', '-l'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc == 2:
            logging.warning('Not ssh-agent is running.')
        if rc == 1:
            logging.warning('Not public key in the ssh-agent')


def main():  # pylint: disable=too-many-statements
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-s', '--sudo', action='store_true', default=0)
    parser.add_argument('-c', '--config', default='~/.genboxrc')
    parser.add_argument('--version', action='version', version=__version__)
    sps = parser.add_subparsers(dest='command')

    sp = sps.add_parser('enter', help='enter a genbox')
    sp.add_argument('-i', '--image', help="default='docker.wyplay.com/tools/genbox'")
    sp.add_argument('-t', '--version', help="default='latest'")
    sp.add_argument('-q', '--portage-image', help="default='docker.wyplay.com/tools/genbox-portage'")
    sp.add_argument('-w', '--portage-version', help="default='same as --version'")
    sp.add_argument('-u', '--user-mode', action='store_true', help='enter the genbox as current user')
    sp.add_argument('-s', '--share-portage', help='reuse /usr/portage volume from another genbox')
    sp.add_argument('-g', '--share-targets', help='reuse /usr/targets volume from another genbox')
    sp.add_argument('--no-targets-volume', action='store_true')
    sp.add_argument('-n', '--no-attach', action='store_true', help=argparse.SUPPRESS)
    sp.add_argument(
        '-v', '--volume', action='append', default=[], help='additional volumes (same syntax as docker run --volume)'
    )
    sp.add_argument('-p', '--privileged', action='store_true', help='run container in privileged mode')
    sp.add_argument('name')

    sp = sps.add_parser('exec', help='execute a command in a genbox')
    sp.add_argument('-u', '--user-mode', action='store_true', help='enter the genbox as current user')
    #sp.add_argument('-p', '--privileged', action='store_true', help='run container in privileged mode')
    sp.add_argument('name')
    sp.add_argument('cmd', nargs=argparse.REMAINDER)

    sp = sps.add_parser('setup', help='reset genbox .gitconfig, .hgrc, and .ssh/config')
    sp.add_argument(
        '-f', '--force', action='store_true', help='override .gitconfig, .hgrc and .ssh/config in the genbox'
    )
    sp.add_argument('name')

    sp = sps.add_parser('rm', help='remove a genbox')
    sp.add_argument('-v', '--volumes', action='store_true')
    sp.add_argument('-f', '--force', action='store_true')
    sp.add_argument('name')

    sp = sps.add_parser('available', help='list available genbox versions')
    sp.add_argument('-i', '--image', default='docker.wyplay.com/tools/genbox')

    sp = sps.add_parser('ls', help='list installed genbox')
    sp.add_argument('-o', '--orphans', action='store_true', help='list orpharn volumes')

    sp = sps.add_parser('help')

    args = parser.parse_args()

    checks = SanityCheck()

    if checks.pre_check():
        return 1

    init_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'help':
        parser.print_help()
        return 0

    try:
        logging.getLogger('gbx.ui').info('=' * 68)
        logging.getLogger('gbx.ui').info('%s started with \'%s\'', __version__, ''.join(sys.argv[1:]))

        cfg = MergeConfig(args)

        if checks.check(cfg):
            return 1

        getattr(App(), args.command)(cfg)
    except:
        logging.getLogger('gbx.ui').exception('An unhandled exception happened :(')
        raise

    return 0
