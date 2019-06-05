# TODO load log from disk
class RollingLog():
    """RollingLog class - Keep a sized, first in, first out log.

    Attributes:
        size (int) - number of log entries to keep track of
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
