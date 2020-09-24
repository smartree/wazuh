#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import socket
import logging
import json
import argparse
import atexit
import readline
import struct
import textwrap


def main():

    # Parse cmdline args
    parser = init_argparse()
    args = parser.parse_args()

    # Default logger configs
    logger_level = 'INFO'
    logger_fmt = '%(message)s'

    # Debug level if requested
    if args.debug:
        logger_level = 'DEBUG'
        logger_fmt = '%(asctime)-15s %(module)s[%(levelname)s] %(message)s'

    # Set logging configs
    logging.basicConfig(format=logger_fmt, level=logger_level)

    if args.version:
        logging.info('%s', Wazuh.get_description())
        logging.info('%s', Wazuh.get_license())
        sys.exit(0)

    w_logtest = WazuhLogtest()
    logging.info('Starting wazuh-logtest %s', Wazuh.get_version_str())
    logging.info('Type one log per line')

    # Cleanup: remove session before exit
    atexit.register(w_logtest.remove_last_session)

    session_token = ""
    while True:
        # Get user input
        try:
            event = input()
        except EOFError:
            continue

        # Avoid empty events
        if not event:
            continue

        # Process log event
        try:
            output = w_logtest.process_log(event, session_token)
        except ValueError:
            logging.error('Error when handling output')
            continue
        except ConnectionError:
            logging.error('Error when connecting with logtest')
            continue

        # Check and alert to user if new session was created
        if session_token and session_token != output['token']:
            logging.warning('New session was created:')

        # Continue using last available session
        session_token = output['token']

        # Show wazuh-logtest output
        WazuhLogtest.show_output(output)


class WazuhDeamonProtocol:
    def __init__(self, version="1", origin_module="wazuh-logtest", module_name="wazuh-logtest"):
        self.protocol = dict()
        self.protocol['version'] = 1
        self.protocol['origin'] = dict()
        self.protocol['origin']['name'] = origin_module
        self.protocol['origin']['module'] = module_name

    def wrap(self, command, parameters):
        msg = self.protocol
        msg['command'] = command
        msg['parameters'] = parameters
        str_msg = json.dumps(msg)
        return str_msg

    def unwrap(self, msg):
        json_msg = json.loads(msg)
        data = json_msg['data']
        return data


class WazuhSocket:
    def __init__(self, file):
        self.file = file

    def send(self, msg):
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(self.file)
            self.socket.send(struct.pack("<I", len(msg)) + msg.encode())
            size = struct.unpack("<I", self.socket.recv(4, socket.MSG_WAITALL))[0]
            recv_msg = self.socket.recv(size, socket.MSG_WAITALL)
            self.socket.close()
            return recv_msg
        except ConnectionError:
            raise


class WazuhLogtest:
    def __init__(self, location="master->/var/log/syslog", log_format="syslog"):
        self.protocol = WazuhDeamonProtocol()
        self.socket = WazuhSocket('/var/ossec/queue/ossec/logtest')
        self.fixed_fields = dict()
        self.fixed_fields['location'] = location
        self.fixed_fields['log_format'] = log_format
        self.last_token = ""

    def process_log(self, log, token=None):
        data = self.fixed_fields
        if token:
            data['token'] = token
        data['event'] = log
        request = self.protocol.wrap('log_processing', data)
        recv_packet = self.socket.send(request)
        reply = self.protocol.unwrap(recv_packet)
        self.last_token = reply['token']
        return reply

    def remove_session(self, token):
        data = self.fixed_fields
        data['token'] = token
        logging.debug('Removing session with token %s.', data['token'])

        request = self.protocol.wrap('remove_session', data['token'])
        recv_packet = self.socket.send(request)
        reply = self.protocol.unwrap(recv_packet)

        return reply

    def remove_last_session(self):
        if self.last_token:
            self.remove_session(self.last_token)

    def show_output(output):
        logging.info(json.dumps(output, indent=2))


class Wazuh:
    def get_initconfig(field, path="/etc/ossec-init.conf"):
        initconf = dict()
        with open(path) as f:
            for line in f.readlines():
                key, value = line.rstrip("\n").split("=")
                initconf[key] = value.replace("\"", "")
        return initconf[field]

    def get_version_str():
        return Wazuh.get_initconfig('VERSION')

    def get_description():
        return 'Wazuh {} - Wazuh Inc.'.format(Wazuh.get_version_str())

    def get_license():
        return textwrap.dedent('''
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License (version 2) as
        published by the Free Software Foundation. For more details, go to
        https://www.gnu.org/licenses/gpl.html
        ''')


def init_argparse():
    parser = argparse.ArgumentParser(
        description="Tool for developing, tuning, and debugging rules."
    )
    parser.add_argument(
        "-V", help='Version and license message',
        action="store_true",
        dest='version'
    )
    parser.add_argument(
        "-d", help='Execute in debug mode',
        action="store_true",
        dest='debug'
    )
    return parser


if __name__ == "__main__":
    main()
