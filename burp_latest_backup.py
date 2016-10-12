#!/usr/bin/python2
import json
import sys
import re
import datetime
import subprocess
import socket
import os
import fcntl

def read_process(process,eol_string):
    buffer = ""
    line = ""
    fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    while True:
        try:
            line = process.stdout.readline()
            buffer += line
            if eol_string == line:
                break
        except IOError as e:
            if process.poll() != 0 and process.poll() != None:
                break
            pass
    return buffer

def read_cache():
    try:
        f = open('/var/tmp/burp_latest_backup_cache','r')
        return f.read()
        f.close()
    except:
        return '0'

def write_cache(timestamp):
    #  When polling during a backup, the binary cannot connect.
    #  It does not means there is no backup available.  So use a cache
    f = open('/var/tmp/burp_latest_backup_cache','w')
    f.write(timestamp)
    f.close()
BURP_REGEX_TIMESTAMP = '([0-9]{7}) ([0-9]{4}-(?:0[1-9]|1[012])-(?:0[1-9]|[12][0-9]|3[01])) ((?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])'

def get_burp1_latest_timestamp():
    json = get_burp1_json()
    latest_timestamp = parse_burp1_json(json)
    return latest_timestamp

def get_burp1_json():
    burp_command = ("/usr/sbin/burp", "-a", "list", "-j")
    burp_json_output = subprocess.Popen(burp_command,stdout=subprocess.PIPE).communicate()[0]
    data = json.loads(burp_json_output)

    return data

def parse_burp1_json(json_object):
    BURP_REGEX_TIMESTAMP = '([0-9]{7}) ([0-9]{4}-(?:0[1-9]|1[012])-(?:0[1-9]|[12][0-9]|3[01])) ((?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])'
 
    latest_burp_timestamp = json_object['backups'][-1]['timestamp']
 
    p = re.compile(BURP_REGEX_TIMESTAMP) # parse the date yyyy-mm-dd
    m = p.search(latest_burp_timestamp)
    latest_burp_datetime = datetime.datetime.strptime(m.group(2) + ' ' + m.group(3), '%Y-%m-%d %H:%M:%S') # return the datetime part of the burp timestamp
    latest_burp_datetime_epoch = latest_burp_datetime.strftime('%s')

    return latest_burp_datetime_epoch
 
def get_burp2_latest_timestamp():
    json = get_burp2_json()
    latest_timestamp = float(parse_burp2_json(json))
    # The burp monitor does not return the epoch format in UTC, but in server localtime.
    # So convert it so we output it in UTC
    latest_timestamp_utc = datetime.datetime.utcfromtimestamp(latest_timestamp).strftime('%s')
    return latest_timestamp_utc
        
def get_burp2_json():
    burp_command = ("/usr/sbin/burp","-a","monitor")

    # Make sure output is clean
    process = subprocess.Popen(burp_command, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    read_process(process,"{ \"logline\": \"in monitor\" }\n")

    fqdn = socket.getfqdn()
    burp_request = "c:{fqdn}\n".format(**locals())
    process.stdin.write(burp_request)
    process.stdin.flush()
    burp_json_output = read_process(process,"}\n")
    process.terminate()
    try:
        data = json.loads(burp_json_output)
    except ValueError:
        data = json.loads('[]')
        pass

    return data

def parse_burp2_json(json_object):
    try:
        for backup in json_object['clients'][0]['backups']:
            if 'current' in backup['flags']:
                latest_backup = str(backup['timestamp'])
                write_cache(latest_backup)
                break
    except TypeError:
        latest_backup = read_cache()

    return latest_backup

def get_burp_version():
    burp_command = ("/usr/sbin/burp","-v")
    process = subprocess.Popen(burp_command, stdout=subprocess.PIPE)
    burp_version = process.communicate()[0]

    if 'burp-1' in burp_version:
        return 1
    elif 'burp-2' in burp_version:
        return 2
    raise
 
if __name__ == "__main__":
 
    burp_version = get_burp_version()
    
    try:
        if burp_version == 1:
            timestamp = get_burp1_latest_timestamp()
        elif burp_version == 2:
            timestamp = get_burp2_latest_timestamp()
        print timestamp
    except:
        sys.stderr.write("Unexpected error: {0}".format(sys.exc_info()[0]))
        raise
        sys.exit(1)

