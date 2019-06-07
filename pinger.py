#!/usr/bin/env python3

"""
pinger - ping hosts. http api to query results.
"""

import os
import sys
import json
import struct
import socket
import argparse

from time import time
from subprocess import call
from multiprocessing import Pool
from textwrap import dedent

from twisted.web import server, resource
from twisted.web.resource import Resource
from twisted.internet import reactor

from rollinglog.rollinglog import RollingLog
from settings.settings import Settings


# Lol globals.
LOG = RollingLog(Settings.get("logsize"))


def hostname_to_ip(hostname):
    """hostname_to_ip() - Resolve a hostname.

    Args:
        hostname (str) - Hostname to resolve.

    Returns:
        String containing IP address in dotted quad notation on success.
        None if hostname could not be resolved.
    """
    try:
        resolved = socket.getaddrinfo(hostname, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    return resolved[0][4][0]


def valid_ipv4_address(ip_address):
    """valid_ip_address() - Validate an IPv4 address.

    Args:
        ip_address (str) - IP address to validate.

    Returns:
        True if ip_address is valid.
        False if ip_address is invalid.
    """
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def ip_to_long(ip_address):
    """ip_to_long() - Convert IP address to decimal.

    Args:
        ip_address (str) - IP address in dotted quad notation.

    Returns:
        Decimal representation of ip_address.
    """
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    """long_to_ip() - Convert decimal number to an IP address.

    Args:
        ip_address (int) - Number representing IP address.

    Returns:
        String containing IP address in dotted quad notation.
    """
    tmp = struct.pack("!L", ip_address)
    return socket.inet_ntoa(tmp)


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


class PingerAPIHelp(Resource):
    """PingerAPIHelp() - Display API help."""
    @staticmethod
    def render_GET(request):
        """Process GET request.

        Args:
            request (twisted Request object) - Required, but not used.

        Returns:
            String containing HTML of the help menu.
        """
        output = """\
        <html>
        <head><title>Pinger</title></head>
        <body>
        <h1>Pinger</h1>
        <h2>Available API calls</h2>
        <p>/elapsed - provide timeframe for scan results</p>
        <p>/up - show current alive hosts and latency</p>
        <p>/down - show current down hosts</p>
        <p>/stats - show up statistics</p>
        <p>/check/host=ip - give current status of ip</p>
        </body>
        </html>
        """
        return dedent(output).encode("utf-8")


class PingerAPIElapsed(Resource):
    """PingerAPIElapsed() - Get elapsed time of current set of data."""
    @staticmethod
    def render_GET(request):
        """Process GET request.

        Args:
            request (twisted Request object) - required, but not used.

        Returns:
            JSON string containing "elapsed": <seconds>
        """
        elapsed = {"elapsed": 0}
        elapsed["elapsed"] = sum(entry[0] for entry in LOG.log if entry[0])
        return json.dumps(elapsed).encode("utf-8")


class PingerAPICheck(Resource):
    """PingerAPICheck() - Check if a host is up/down and provide stats."""
    @staticmethod
    def render_GET(request):
        """Process GET request.

        Args:
            request (twisted Request object) - Contains args, cookies, etc.

        Returns:
            JSON string containing information about the host
        """
        check = {}
        try:
            host = request.args[b"host"]
            check["host"] = host[0].decode()
        except KeyError:
            return b"{}"

        # Search for host in log. Bail out if a match isnt found
        found = False
        for entry in LOG.log[-1][1]:
            if entry[0] == host[0].decode():
                check["alive"] = True if entry[1] else False
                found = True
                break
        if found is False:
            return b"{}"

        # Calculate average uptime.
        elapsed = 0
        uptime = 0
        for log_entry in LOG.log:
            if log_entry[0] is None:
                continue
            elapsed += log_entry[0]
            for item in log_entry[1]:
                if item[0] == host[0].decode() and item[1]:
                    uptime += log_entry[0]

        check["uptime_percent"] = (uptime / elapsed) * 100
        check["elapsed"] = elapsed
        return json.dumps(check).encode("utf-8")


class PingerAPIUp(Resource):
    """PingerAPIUp() - Provide a list of hosts that are currently up."""
    @staticmethod
    def render_GET(request):
        """Process GET request.

        Args:
            request (twisted Request object) - Unused, but requried.

        Returns:
            JSON object of a list of currently alive hosts and their last
            reported latency.
        """
        alive = {}
        for host in LOG.log[-1][1]:
            if host[1]:
                alive[host[0]] = host[1]
        return json.dumps(alive).encode("utf-8")


class PingerAPIDown(Resource):
    """PingerAPIDown() - Provide a list of hosts that are currently down."""
    @staticmethod
    def render_GET(request):
        """Process GET request

        Args:
            request (twisted Request object) - required, unused.

        Returns:
            JSON list of tracked, but down hosts.
        """
        dead = [host[0] for host in LOG.log[-1][1] if host[1] is None]
        return json.dumps(dead).encode("utf-8")


class PingerAPIStats(Resource):
    """PingerAPIStats() - Show stats of all tracked hosts."""
    @staticmethod
    def render_GET(request):
        """Process GET request

        Args:
            request (twisted Request object) - required, unused.

        Returns:
            JSON string showing stats of currently tracked hosts.

        Example output:
            {"192.168.1.1": 100.0, "192.168.1.2": 0.0, "elapsed": 31.124125}
        """
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
        return json.dumps(stats).encode("utf-8")


def parse_args():
    """parse_args() - Parse CLI arguments

    Args:
        None.

    Returns:
        Nothing.
    """
    description = "pinger.py by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("hosts",
                        nargs="*",
                        help="hosts and networks (cidr) to ping")
    parser.add_argument("-p",
                        "--port",
                        action="store",
                        required=False,
                        help="port number for HTTP API")
    parser.add_argument("-n",
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

    if args.port:
        Settings.set("port", int(args.port))

    if args.processes:
        Settings.set("processes", int(args.processes))

    if args.logsize:
        Settings.set("logsize", int(args.logsize))

    if not args.hosts:
        print("ERROR: Must supply hosts/networks to scan.\n", file=sys.stderr)
        parser.print_help(sys.stderr)
        exit(os.EX_USAGE)

    # Create list of IPs to scan.
    # TODO nmap style IP addresses too: 192.168.0-10.*
    hosts = set()
    for host in args.hosts:
        if "/" in host:
            network, cidrmask = host.split("/")
            if int(cidrmask) < 0 or int(cidrmask) > 32 or not valid_ipv4_address(network):
                print("ERROR: Invalid network: %s\n" % host, file=sys.stderr)
                parser.print_help(sys.stderr)
                exit(os.EX_USAGE)

            inverse = 0xffffffff << (32 - int(cidrmask)) & 0xffffffff
            first = ip_to_long(network) & inverse
            last = first | (~inverse & 0xffffffff)

            for address in range(first + 1, last):
                hosts.add(long_to_ip(address))

        elif valid_ipv4_address(host):
            hosts.add(host)

        else:
            resolved = hostname_to_ip(host)
            if resolved:
                hosts.add(resolved)
            else:
                print("ERROR: Unable to resolve %s\n" % host, file=sys.stderr)
                parser.print_help(sys.stderr)
                exit(os.EX_USAGE)
    Settings.set("hosts", hosts)


def main():
    """main() - main function

    Args:
        None.

    Returns:
        Nothing.
    """
    parse_args()

    # TODO load previous state from disk
    for _ in range(LOG.size):
        LOG.add((None, []))

    # Set up HTTP API
    wwwroot = Resource()
    wwwroot.putChild(b"", PingerAPIHelp())
    wwwroot.putChild(b"elapsed", PingerAPIElapsed())
    wwwroot.putChild(b"check", PingerAPICheck())
    wwwroot.putChild(b"up", PingerAPIUp())
    wwwroot.putChild(b"down", PingerAPIDown())
    wwwroot.putChild(b"stats", PingerAPIStats())
    reactor.listenTCP(Settings.get("port"), server.Site(wwwroot))

    # START THE REACTOR!@#$
    reactor.callInThread(check_hosts, Settings.get("hosts"))
    reactor.run()


if __name__ == "__main__":
    main()
