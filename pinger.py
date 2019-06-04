#!/usr/bin/env python3

import os
from subprocess import call
from time import time
from multiprocessing import Pool

from twisted.web import server, resource
from twisted.internet import reactor


# TODO log -> disk
# TODO load log from disk on startup
# TODO write log to disk on shutdown
class RollingLog():
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

LOG = RollingLog(10)


def ping(host):
    devnull = open(os.devnull, "w")
    elapsed = None

    start_time = time()
    if call(['ping', '-c 1 -W 1', host], stdout=devnull, stderr=devnull) == 0:
        elapsed = time() - start_time

    return (host, elapsed)


def check_hosts(ips, threads=32):
    start_time = time()
    pool = Pool(threads)
    output = pool.map(ping, ips)

    pool.close()
    pool.join()
    finish_time = time() - start_time

    LOG.add((finish_time, output))

    current_state = LOG.log[-1]
    previous_state = LOG.log[-2]

    current_hosts = current_state[1]
    previous_hosts = previous_state[1]

    for current in current_hosts:
        for previous in previous_hosts:
            if current[0] == previous[0]: # hosts match
                current_up = True if current[1] else False
                previous_up = True if previous[1] else False
                if current_up != previous_up: # state changed!
                    # TODO probably can figure out something useful
                    #      to do here, log it, etc.
                    print()
                    print("state changed:", current, previous)
                    print()
    # lolloop
    reactor.callInThread(check_hosts, ips, threads=threads)


class PingerAPI(resource.Resource):
    isLeaf = True
    # TODO is host up?
    # TODO percentage for up
    # TODO percentage for down
    # TODO return time range for currently held data
    def render_GET(self, request):
        return "".encode("utf-8")


def main():
    ips = []
    for x in range(5):
        ips.append("192.168.10." + str(x))

    for x in range(LOG.size):
        LOG.add((None, []))

    # Set up API
    http_api = server.Site(PingerAPI())
    reactor.listenTCP(8888, http_api)

    reactor.callInThread(check_hosts, ips)
    reactor.run()


if __name__ == "__main__":
    main()

