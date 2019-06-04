#!/usr/bin/env python3

"""
pinger - ping hosts. http api to query results.
"""
import os
import json
import argparse

from time import time
from subprocess import call
from multiprocessing import Pool

from twisted.web import server, resource
from twisted.internet import reactor


class Settings(object):
    """Settings object - store application settings and methods to
                         manipulate them.
    """
    __config = {
        "logsize": 100,
        "processes": 32,
    }

    __settings = [
        "processes",
    ]

    @staticmethod
    def set(name, value):
        if name in Settings.__settings:
            Settings.__config[name] = value
        else:
            raise NameError("Not a valid setting: %s" % name)

    @staticmethod
    def get(name):
        return Settings.__config[name]

# TODO load log from disk
class RollingLog():
    """RollingLog class - Keep a sized, first in, first out log.

    Attributes:
        size (int) - number of log entries to kee ptrack of
    """
    def __init__(self, size):
        self.size = size
        self.log = []

    def add(self, data):
        self.log += [data]
        if len(self.log) > self.size:
            self.log = self.log[-1 * self.size:]

    def write(self, path):
        with open(path, "w") as logfile:
            for line in self.log:
                logfile.write(str(line) + "\n")

    def clear(self):
        self.log = []

LOG = RollingLog(Settings.get("logsize"))


def ping(host):
    """ping() - ping a host using the ping binary in $PATH

    Args:
        host (str) - host/ip to ping

    Returns:
        (host, elapsed) (str, int) - tuple with host and response time.
    """
    elapsed = None
    start_time = time()

    with  open(os.devnull, "w") as null:
        if call(['ping', '-c 1 -W 1', host], stdout=null, stderr=null) == 0:
            elapsed = time() - start_time

    return (host, elapsed)


def check_hosts(ips):
    """check_hosts() - ping list of hosts, log them, and do things to said hosts

    Args:
        ips (list) - list of ips to ping
        processes (int) - number of ping processes to execute at a time.

    Returns:
        Nothing, however this calls itself at the end in order to achieve
        a continuous scan with as little effort from my end as possible.
    """
    processes = Settings.get("processes")
    print(processes)
    start_time = time()
    pool = Pool(processes)
    output = pool.map(ping, ips)

    pool.close()
    pool.join()
    finish_time = time() - start_time

    LOG.add((finish_time, output))

    current_state = LOG.log[-1]
    previous_state = LOG.log[-2]

    current_hosts = current_state[1]
    previous_hosts = previous_state[1]

    if previous_hosts == []:
        for current in current_hosts:
            if current[1]:
                print("up", current)

    for current in current_hosts:
        for previous in previous_hosts:
            if current[0] == previous[0]: # hosts match
                current_up = True if current[1] else False
                previous_up = True if previous[1] else False
                if current_up != previous_up: # state changed!
                    # TODO "traps"
                    print("up" if current_up else "down", current)
    # lolloop
    reactor.callInThread(check_hosts, ips)


class PingerAPI(resource.Resource):
    """PingerAPI class - twisted resource to handle API requests"""
    isLeaf = True

    @staticmethod
    def render_GET(request):
        #print(request.requestHeaders)
        if request.uri == b"/":
            # display help
            output = "<html>\n<head><title>Pinger</title></head>\n<body>\n"
            output += "<h1>Pinger</h1>\n"
            output += "<h2>Available API calls</h2>\n"
            output += "<p>/elapsed - provide timeframe for scan results</p>\n"
            output += "<p>/up - show current alive hosts and latency</p>\n"
            output += "<p>/down - show current down hosts</p>\n"
            output += "<p>/stats - show up statistics</p>\n"
            output += "<p>/check/host=ip - give current status of ip</p>"
            output += "</body>\n</html>"
            return output.encode("utf-8")

        if request.path == b"/elapsed":
            # Show how much time in seconds that our log represents
            elapsed = {"elapsed": 0}
            for log_entry in LOG.log:
                if log_entry[0]:
                    elapsed["elapsed"] += log_entry[0]

            output = json.dumps(elapsed)
            return output.encode("utf-8")

        if request.path == b"/check":
            # Show details for a host
            check = {}
            try:
                host = request.args[b"host"]
                check["host"] = host[0].decode()
            except KeyError:
                return b"{}"

            current_set = LOG.log[-1]

            found = False
            for x in current_set[1]:
                if x[0] == host[0].decode():
                    check["alive"] = True if x[1] else False
                    found = True
                    break
            if found is False:
                return b"{}"

            if found:
                elapsed = 0
                uptime = 0
                for log_entry in LOG.log:
                    if log_entry[0]:
                        elapsed += log_entry[0]
                        for x in log_entry[1]:
                            if x[0] == host[0].decode():
                                if x[1]:
                                    uptime += log_entry[0]
                uptime_percent = (uptime / elapsed) * 100
                check["uptime_percent"] = uptime_percent
                check["elapsed"] = elapsed

            output = json.dumps(check)
            return output.encode("utf-8")

        if request.path == b"/up":
            # Show current hosts responding to pings w/ latency
            current_set = LOG.log[-1]
            alive = {}
            for host in current_set[1]:
                if host[1]:
                    alive[host[0]] = host[1]
            output = json.dumps(alive)
            return output.encode("utf-8")

        if request.path == b"/down":
            # Show current down hosts
            current_set = LOG.log[-1]
            dead = []
            for host in current_set[1]:
                if host[1] is None:
                    dead += [host[0]]
            output = json.dumps(dead)
            return output.encode("utf-8")

        if request.path == b"/stats":
            # Show percentage of elapsed time from the log that hosts are up.
            # Example output:
            # {"192.168.1.1": 100.0, "192.168.1.2": 0.0, "elapsed": 31.124125}
            elapsed = 0
            stats = {}
            for log_entry in LOG.log:
                if log_entry[0] is None:
                    continue
                elapsed += log_entry[0]
                for host in log_entry[1]:
                    if host[1]:
                        try:
                            stats[host[0]] += log_entry[0]
                        except KeyError:
                            stats[host[0]] = log_entry[0]
                    else:
                        try:
                            stats[host[0]] += 0
                        except KeyError:
                            stats[host[0]] = 0

            # Calculate percentage uptime for each host
            for host in stats:
                stats[host] = (stats[host] / elapsed) * 100

            stats["elapsed"] = elapsed

            output = json.dumps(stats)
            return output.encode("utf-8")

        return b"<html><h1>Error</h1><p>invalid URI: %s</p></html>" % request.uri

def parse_args():
    description = "pinger.py by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("-p",
                        "--processes",
                        action="store",
                        required=False,
                        help="number of ping processes to use")
    parser.add_argument("-s",
                        "--logsize",
                        action="store",
                        required=False,
                        help="size of RollingLog")
    args = parser.parse_args()

    if args.processes:
        Settings.set("processes", int(args.processes))

    if args.logsize:
        Settings.set("logsize", int(args.logsize))


def main():
    """main() - main function

    Args:
        None

    Returns:
        Nothing
    """

    parse_args()

    ips = []
    for x in range(1, 255):
        ips.append("192.168.59." + str(x))

    ips = set(ips)

    for _ in range(LOG.size):
        LOG.add((None, []))

    # Set up API
    http_api = server.Site(PingerAPI())
    reactor.listenTCP(8888, http_api)

    reactor.callInThread(check_hosts, ips)
    reactor.run()


if __name__ == "__main__":
    main()
