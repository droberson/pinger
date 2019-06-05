class Settings(object):
    """Settings object - store application settings and methods to
                         manipulate them.
    """
    __config = {
        "hosts": [],
        "logsize": 100,
        "port": 8888,
        "processes": 32,
    }

    __settings = [
        "hosts",
        "logsize",
        "port",
        "processes",
    ]

    @staticmethod
    def set(name, value):
        """Setting.set() - Set a setting.

        Args:
            name (str) - Name of setting to set.
            value - Value of setting.

        Returns:
            Nothing.
        """
        if name in Settings.__settings:
            Settings.__config[name] = value
        else:
            raise NameError("Not a valid setting: %s" % name)

    @staticmethod
    def get(name):
        """Settings.get() - Retrieve the value of a setting

        Args:
            name (str) - Name of setting to retrieve.

        Returns:
            Value of setting.
        """
        return Settings.__config[name]
