from argparse import ArgumentParser, ArgumentError, FileType, \
    _get_action_name as argparse_get_action_name
from subprocess import Popen, PIPE as subprocess_PIPE
from time import sleep
import json
import sys

import pyrax
import requests


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('-c', '--config',
        type=FileType('r'), help='JSON settings file', dest='config_file')

    settings_map = {
        'load_balancer': parser.add_argument('-l', '--load-balancer',
            type=str, help='Load balancer to query for server list'),
        'rackuser': parser.add_argument('-u', '--rackuser',
            type=str, help='Rackspace API username'),
        'rackpass': parser.add_argument('-p', '--rackpass',
            type=str,
            help=('Rackspace API key (recommended) or ' +
                  'password (not recommended)')),
        'script_sync': parser.add_argument('-s', '--script', dest='script',
            type=str, help='Script to run in each server of the load balancer'),
        'sshuser': parser.add_argument('--sshuser',
            type=str, default='root',
            help='User used while connecting using SSH'),
        'script_sync_args': parser.add_argument('-a', '--args',
            dest='script_args',
            type=str, required=False,
            help='Additional arguments for the shell script.'),
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
                'line `--{argument}` or as a key "{key}" in the settings '
                'file). [{config_src}]'.format(
                    key=key,
                    argument=argparse_get_action_name(action),
                    config_src=config_file_source))

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


def server_public_addr(server):
    try:
        return server.accessIPv4
    except AttributeError:
        try:
            return [addr for addr in server.addresses['public']
                if addr['version'] == 4][0]['addr']
        except (KeyError, IndexError):
            raise ValueError(
                'Unable to get public address of server {server}'.format(
                    server=server))


def run_update_script(server, arguments):
    ssh_process_exit_code = 255
    retries = 4
    address = server.accessIPv4
    script_args = str(arguments.script_args)

    while ssh_process_exit_code != 0 and retries > 0:
        ssh_process = Popen(
            [
                'ssh',
                '-q',
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
        print 'ssh {sshuser}@{address} remote command exit code: {code}'.format(
            sshuser=arguments.sshuser,
            address=address,
            code=ssh_process_exit_code,
        )
    else:
        print ('>> FAILED: ssh {sshuser}@{address} ' +
               'remote command exit code: {code}').format(
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
    pyrax.cloud_loadbalancers = pyrax.connect_to_cloud_loadbalancers()

    load_balancer = None
    for balancer in pyrax.cloud_loadbalancers.list():
        if arguments.load_balancer in (str(balancer.id), balancer.name):
            load_balancer = balancer
            break

    if not load_balancer:
        raise ValueError('Load balancer with ID/Name "{id}" not found'.format(
            id=arguments.load_balancer,
        ))

    for server in [node.get_device() for node in load_balancer.nodes]:
        run_update_script(server, arguments)


if __name__ == '__main__':
    main()
