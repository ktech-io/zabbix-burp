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

def read_process(process, eol_string):
    """Read the process until there is nothig to read anymore"""
    output = ""
    line = ""
    fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    while True:
        try:
            line = process.stdout.readline()
            output += line
            if eol_string == line:
                break
        except IOError:
            if process.poll() != 0 and process.poll() != None:
                break
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
    latest_timestamp_utc = datetime.datetime.utcfromtimestamp(latest_timestamp).strftime('%s')
    return latest_timestamp_utc

def get_burp2_json():
    """Read output of the command"""
    burp_command = ("/usr/sbin/burp", "-a", "monitor")

    # Make sure output is clean
    process = subprocess.Popen(burp_command, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    read_process(process, "{ \"logline\": \"in monitor\" }\n")

    fqdn = socket.getfqdn()
    burp_request = "c:{0}\n".format(fqdn)
    process.stdin.write(burp_request)
    process.stdin.flush()
    burp_json_output = read_process(process, "}\n")
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

