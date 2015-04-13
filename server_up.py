from copy import deepcopy, copy
from uuid import uuid4
from argparse import ArgumentParser, ArgumentError, FileType, _get_action_name as argparse_get_action_name
from subprocess import Popen, PIPE as subprocess_PIPE
from threading import Thread
from time import sleep
import json
import sys

import pyrax
import requests


def server_public_addr(server):
    try:
        return [
            addr
            for addr in server.addresses['public']
            if addr['version'] == 4
        ][0]['addr']
    except (KeyError, IndexError):
        return getattr(server, 'accessIPv4', None)


class ServerWatcherThread(Thread):
    expected_statuses = ['active', 'error', 'available', 'completed']

    def __init__(self, server, initial_ip=None, *callback_args, **callback_kwargs):
        super(ServerWatcherThread, self).__init__()
        self.server = server
        self.initial_ip = initial_ip
        self.callback_args = callback_args
        self.callback_kwargs = callback_kwargs

    def run(self):
        while not getattr(self.__class__, 'stop_threads', False):
            sleep(2)
            printed_status = False
            printed_access = False
            self.server = pyrax.cloudservers.servers.get(self.server.id)
            if not self.server.status.lower() in self.expected_statuses:
                if not printed_status:
                    print (
                        'Waiting for server {name} ({id}) to be ready... ' +
                        '(Status: {status})').format(
                            name=self.server.name,
                            id=self.server.id,
                            status=self.server.status,
                            address=getattr(
                                self.server, 'accessIPv4', self.initial_ip),
                        )
                    printed_status = True
                continue

            if self.server.status in ('error', 'ERROR', ):
                raise Exception((
                    'Server {name} ({id}) finished with ' +
                    '"ERROR" status').format(
                    name=self.server.name,
                    id=self.server.id,
                ))

            if getattr(self.server, 'accessIPv4', self.initial_ip) == server_public_addr(self.server):
                if not printed_access:
                    print (
                        'Waiting for server {name} ({id}) to be ' +
                        'accessible... (Current: {address})').format(
                            name=self.server.name,
                            id=self.server.id,
                            status=self.server.status,
                            address=getattr(self.server, 'accessIPv4', self.initial_ip),
                        )
                    printed_access = True
                continue

            # All tests passed, break the pooling cycle
            break

        self.server = pyrax.cloudservers.servers.get(self.server.id)


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('-c', '--config',
        type=FileType('r'), help='JSON settings file', dest='config_file')

    settings_map = {
        'count': parser.add_argument('-n', '--count',
            type=int, help='How many servers to create'),
        'hostname': parser.add_argument('-H', '--hostname',
            type=str, help=('Server hostname. Use `{hash}` to specify ' +
            'where to place the generated UUID.')),
        'script_up':parser.add_argument('-s', '--script', dest='script',
            type=str, help='Script to run in each server when created'),
        'rackuser': parser.add_argument('-u', '--rackuser',
            type=str, help='Rackspace API username'),
        'rackpass': parser.add_argument('-p', '--rackpass',
            type=str, help=('Rackspace API key (recommended) or ' +
            'password (not recommended)')),
        'sshkey': parser.add_argument('-k', '--sshkey',
            type=str, help='Name of the SSH Key to include in the server'),
        'rackzone': parser.add_argument('-z', '--rackzone',
            type=str, help='Rackspace availability zone', default='DFW'),
        'rackdistro': parser.add_argument('-d', '--rackdistro',
            type=str, help='Rackspace distribution ID',
            default='5cc098a5-7286-4b96-b3a2-49f4c4f82537'),
        'rackflavor': parser.add_argument('-f', '--rackflavor',
            type=str, help='Rackspace flavor ID', default=2),
        'sshuser': parser.add_argument('--sshuser',
            type=str, default='root',
            help='User used while connecting using SSH'),
        'script_up_args': parser.add_argument('-a', '--args',
            dest='script_args', type=str, required=False,
            help='Additional arguments for the Bash script.'),
        'load_balancer': parser.add_argument('-l', '--load-balancer',
            type=str, help='Loadbalancer to which attach the new servers'),
    }

    args = parser.parse_args()
    config_from_file = {}
    config_file_source = None

    if args.config_file:
        config_from_file = json.load(args.config_file)
        config_file_source = 'argument'
    else:
        try:
            with open('./settings.json') as config_file:
                config_from_file = json.load(config_file)
                config_file_source = 'cwd'
        except IOError:
            pass

    for key, action in settings_map.items():
        action.dest = action.dest or key
        if not getattr(args, action.dest, None):
            setattr(args, action.dest, config_from_file.get(key, None))

        if not getattr(args, action.dest, None) and action.required:
            raise ArgumentError(action,
                'Missing argument (must be present as a command '
                'line `--{argument}` or as a key "{key}" in the settings file). '
                '[{config_src}]'.format(
                    key=key,
                    argument=argparse_get_action_name(action),
                    config_src=config_file_source))

    if args.count < 1:
        raise ArgumentError(
            settings_map['count'],
            'Server count must be higher than zero. [{config_src}]'.format(
                config_src=config_file_source))

    if args.count > 1 and not '{hash}' in args.hostname:
        raise ArgumentError(settings_map['hostname'],
            'Hostname value does not contain the `{hash}` placeholder. This is'
            'needed when the `count` arguments is higher than `1`. '
            '[{config_src}]'.format(
                config_src=config_file_source, hash='{hash}'))

    script_response = requests.get(args.script)
    try:
        if not script_response.ok:
            raise ArgumentError(settings_map['script'],
                'Url `{script}` returned a non-OK response: ({status_code}):'
                '{response_content}. [{config_src}]'.format(
                    script=args.script,
                    config_src=config_file_source,
                    status_code=script_response.status_code,
                    response_content=script_response.content,
                ))

        args.script_content = script_response.content
    except requests.ConnectionError, error:
        raise ArgumentError(settings_map['script'],
            ('Url `{script}` raised a network error: {error}. ' +
             '[{config_src}]').format(
                script=args.script,
                config_src=config_file_source,
                error=repr(error),
            ))

    return args


def custom_excepthook(type, value, traceback):
    if type == ArgumentError:
        print str(value)
    elif custom_excepthook.original_excepthook:
        custom_excepthook.original_excepthook(type, value, traceback)


def run_deploy_script(server, arguments):
    ssh_process_exit_code = 255
    retries = 4
    address = server.accessIPv4
    script_args = '{hostname} {args}'.format(
        hostname=arguments.hostname,
        args=arguments.script_args,
    )

    while ssh_process_exit_code != 0 and retries > 0:
        ssh_process = Popen(
            [
                'ssh',
                '-o',
                'StrictHostKeyChecking=no',
                '-t',
                '{sshuser}@{address}'.format(
                    sshuser=arguments.sshuser,
                    address=address
                ),
                'bash -s {script_args}'.format(
                    script_args=script_args,
                ),
            ],
            stdin=subprocess_PIPE,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        ssh_process.communicate(input=arguments.script_content)
        ssh_process_exit_code = ssh_process.wait()
        retries = retries - 1
        if ssh_process_exit_code != 0:
            sleep(2)

    if ssh_process_exit_code == 0:
        print (
            'ssh {sshuser}@{address} remote command ' +
            'exit code: {code}').format(
                sshuser=arguments.sshuser,
                address=address,
                code=ssh_process_exit_code,
            )
    else:
        print (
            '>> FAILED: ssh {sshuser}@{address} remote command ' +
            'exit code: {code}').format(
                sshuser=arguments.sshuser,
                address=address,
                code=ssh_process_exit_code,
            )

    return ssh_process_exit_code


def main():
    custom_excepthook.original_excepthook = sys.excepthook
    sys.excepthook = custom_excepthook

    arguments = get_arguments()

    pyrax.set_setting('identity_type', 'rackspace')
    pyrax.set_credentials(arguments.rackuser, arguments.rackpass)
    pyrax.set_default_region(arguments.rackzone)
    pyrax.cloudservers = pyrax.connect_to_cloudservers()
    pyrax.cloud_loadbalancers = pyrax.connect_to_cloud_loadbalancers()

    flavor_obj = pyrax.cloudservers.flavors.get(arguments.rackflavor)
    distro_obj = pyrax.cloudservers.images.get(arguments.rackdistro)

    load_balancer = None
    for balancer in pyrax.cloud_loadbalancers.list():
        if arguments.load_balancer in (str(balancer.id), balancer.name):
            load_balancer = balancer
            break

    arguments.load_balancer = load_balancer if load_balancer else None
    if not load_balancer:
        print (
            'WARNING: Load balancer "{load_balancer}" not found.' +
            'Continuing without registering any server in any load balancer'
        ).format(
            load_balancer=arguments.load_balancer,
        )

    watchers = []

    for index in xrange(arguments.count):
        # server_arguments = deepcopy(arguments)
        server_arguments = copy(arguments)
        server_arguments.hostname = arguments.hostname.format(hash=uuid4().hex,
            zone=server_arguments.rackzone.lower())
        server = pyrax.cloudservers.servers.create(
            name=server_arguments.hostname,
            image=distro_obj,
            flavor=flavor_obj,
            availability_zone=server_arguments.rackzone,
            key_name=server_arguments.sshkey,
            networks=[
                {'uuid': '11111111-1111-1111-1111-111111111111', },
                {'uuid': '00000000-0000-0000-0000-000000000000', },
            ]
        )
        watcher = ServerWatcherThread(
            server, initial_ip=server_public_addr(server))
        setattr(watcher, 'server_arguments', server_arguments)
        watcher.start()
        watchers.append(watcher)

    for watcher in watchers:
        try:
            watcher.join()
        except KeyboardInterrupt:
            ServerWatcherThread.stop_threads = True
            raise

    for watcher in watchers:
        run_deploy_script(watcher.server, watcher.server_arguments)

    # TODO: Include these new servers into the loadbalancer if any is provided


if __name__ == '__main__':
    main()
