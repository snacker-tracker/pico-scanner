import requests as _requests


def get(url, **kwargs):
    return _requests.get(url, **kwargs)


def post(url, **kwargs):
    return _requests.post(url, **kwargs)
