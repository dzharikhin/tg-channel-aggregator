import os


def is_debug():
    return "true" == os.getenv("DEBUG", "False").lower()
