#!/usr/bin/python2
"""Get the epoch format of the latest burp backup.

This module will parse output of the burp cli and return the output
"""
import json
import sys
import re
import datetime
import subprocess
import socket
import os
import fcntl
import time

def main():
    """Main function"""

    try:
        burp_version = get_burp_version()
        if burp_version == 1:
            timestamp = get_burp1_latest_timestamp()
        elif burp_version == 2:
            timestamp = get_burp2_latest_timestamp()
        print timestamp
    except BaseException as error:
        sys.stderr.write("Unexpected error: {0}\n".format(error))
        sys.exit(1)

###################
# Generic functions

def get_burp_version():
    """Get the burp version"""

    try:
        burp_command = ("/usr/sbin/burp", "-v")
        process = subprocess.Popen(burp_command, stdout=subprocess.PIPE)
        burp_version = process.communicate()[0]
    except OSError:
        raise BaseException("burp binary (/usr/sbin/burp) could not be found")

    if 'burp-1' in burp_version:
        return 1
    elif 'burp-2' in burp_version:
        return 2
    raise BaseException("Unknown burp version '{0}'".format(burp_version))

def flush_buffer(buf, buffer_size=16000):
    """Read the buffer until there is nothig to read anymore"""
    output = ''
    read_bytes = buf.read(buffer_size)
    while read_bytes != '':
        output += read_bytes
        try:
            read_bytes = buf.read(buffer_size)
        except IOError:
            read_bytes = ''
    return output

def read_process(process, eol_regex, buffer_size=16000, timeout=60):
    """Read the process output and exit when regex is found"""
    error_sleep_time = 0.1
    max_error = timeout / error_sleep_time
    error_count = 0
    output = ""
    fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    while process.poll() is None:
        try:
            output += flush_buffer(process.stdout, buffer_size)
            if re.search(eol_regex, output):
                break
        except IOError:
            time.sleep(error_sleep_time)
            error_count = error_count + 1
            if error_count >= max_error:
                break
    try:
        output += flush_buffer(process.stdout, buffer_size)
    except IOError:
        pass
    return output

def read_cache():
    """Check the latest cached data"""
    try:
        cache_file = open('/var/tmp/burp_latest_backup_cache', 'r')
        cached_string = cache_file.read()
        cache_file.close()
    except IOError:
        cached_string = '0'

    return cached_string

def write_cache(timestamp):
    """Write timestamp to cache

    When polling during a backup, the binary cannot connect.
    It does not means there is no backup available.  So use a cache
    """
    cache_file = open('/var/tmp/burp_latest_backup_cache', 'w')
    cache_file.write(timestamp)
    cache_file.close()

###########################
# Burp1 specific functions

def get_burp1_latest_timestamp():
    """Main function for Burp version 1"""
    json_output = get_burp1_json()
    latest_timestamp = parse_burp1_json(json_output)
    return latest_timestamp

def get_burp1_json():
    """Read output of the command"""
    burp_command = ("/usr/sbin/burp", "-a", "list", "-j")
    burp_json_output = subprocess.Popen(burp_command, stdout=subprocess.PIPE).communicate()[0]
    data = json.loads(burp_json_output)

    return data

def parse_burp1_json(json_object):
    """Parse the json"""
    burp_regex_timestamp = ('([0-9]{7}) '
                            '([0-9]{4}-(?:0[1-9]|1[012])-(?:0[1-9]|[12][0-9]|3[01])) '
                            '((?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])'
                           )

    latest_burp_timestamp = json_object['backups'][-1]['timestamp']

    compiled_regex = re.compile(burp_regex_timestamp) # parse the date yyyy-mm-dd
    regex_result = compiled_regex.search(latest_burp_timestamp)
    # return the datetime part of the burp timestamp
    latest_burp_datetime = datetime.datetime.strptime(
        regex_result.group(2) + ' ' + regex_result.group(3),
        '%Y-%m-%d %H:%M:%S'
    )
    latest_burp_datetime_epoch = latest_burp_datetime.strftime('%s')

    return latest_burp_datetime_epoch

###########################
# Burp2 specific functions

def get_burp2_latest_timestamp():
    """Main function for Burp version 2"""
    json_output = get_burp2_json()
    latest_timestamp = float(parse_burp2_json(json_output))
    # The burp monitor does not return the epoch format in UTC, but in server localtime.
    # So convert it so we output it in UTC
    if latest_timestamp != 0:
        latest_timestamp_utc = datetime.datetime.utcfromtimestamp(latest_timestamp).strftime('%s')
    else:
        latest_timestamp_utc = 0
    return latest_timestamp_utc

def get_burp2_json():
    """Read output of the command"""
    burp_command = ("/usr/sbin/burp", "-a", "monitor")

    # Make sure output is clean
    process = subprocess.Popen(burp_command, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    eol_regex = re.compile(r'\n\{ "logline": "in monitor" \}\n')
    read_process(process, eol_regex)


    fqdn = socket.getfqdn()
    burp_request = "c:{0}\n".format(fqdn)
    process.stdin.write(burp_request)
    process.stdin.flush()
    eol_regex = re.compile(r'\n\}\n')
    burp_json_output = read_process(process, eol_regex)

    process.terminate()
    try:
        data = json.loads(burp_json_output)
    except ValueError:
        data = json.loads('[]')

    return data

def parse_burp2_json(json_object):
    """Parse the json"""
    try:
        for backup in json_object['clients'][0]['backups']:
            if 'current' in backup['flags']:
                latest_backup = str(backup['timestamp'])
                write_cache(latest_backup)
                break
    except TypeError:
        latest_backup = read_cache()

    return latest_backup


if __name__ == "__main__":
    main()

