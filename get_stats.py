#!/usr/bin/env python3
"""Acquire stats from GitHub."""
import getpass
import json
import os.path
import re
import time
import urllib.parse
from collections import defaultdict

import requests
import yaml
from pyquery import PyQuery as pq


def logged_in_github_session():
    """Return a logged-in github.com requests session.

    Unfortunately, the unauthenticated search doesn't allow searching across
    all repositories; you have to log in. Additionally, the API doesn't allow
    searching across repositories *at all*, so we have to scrape the website.
    """
    session = requests.session()
    session.headers.update({'User-Agent': 'sorry github :('})

    req = session.get('https://github.com/login')
    assert req.status_code == 200, req.status_code

    m = re.search('name="authenticity_token".+value="(.*?)"', req.text)
    assert m, req.text
    csrf_token = m.group(1)

    req = session.post('https://github.com/session', data={
        'authenticity_token': csrf_token,
        'login': input('GitHub User: '),
        'password': getpass.getpass('GitHub Password: '),
    })

    assert req.status_code == 200, req.status_code
    assert 'Incorrect username' not in req.text, req.text

    return session


def cached(path):
    """Cache a function's output as JSON to disk.

    I'm trying real hard to avoid slamming GitHub with requests by caching
    functions to disk.
    """
    def wrapper(fn):
        def wrapped(*args, **kwargs):
            if os.path.isfile(path):
                with open(path) as f:
                    return json.load(f)
            else:
                result = fn(*args, **kwargs)
                with open(path, 'w') as f:
                    json.dump(result, f, indent=4, sort_keys=True)
                return result
        return wrapped
    return wrapper


@cached('all_repos.json')
def all_repos_using_pre_commit():
    session = logged_in_github_session()
    repos = {}

    page = 1
    while True:
        while True:
            req = session.get(
                'https://github.com/search?' + urllib.parse.urlencode({
                    'q': 'filename:.pre-commit-config.yaml',
                    'type': 'Code',
                    'p': page,
                }),
            )
            if req.status_code == 429:
                print('Hit rate limit, sleeping 120s')
                time.sleep(120)
            else:
                break
        assert req.status_code == 200, req.status_code

        p = pq(req.text)
        results = p('.code-list .title > a[title]')

        if len(results) <= 0:
            break

        for result in results:
            path = result.attrib['href']
            _, owner, name, _ = path.split('/', 3)
            repos['{}/{}'.format(owner, name)] = 'https://github.com' + path

        print('Found {} results (page {})'.format(len(repos), page))
        page += 1

    return repos


def normalize_repo(path):
    """Normalize a git (probably GitHub) repo path.

    >>> normalize_repo('git://github.com/pre-commit/pre-commit-hooks')
    'github.com/pre-commit/pre-commit-hooks'

    >>> normalize_repo('git@github.com:pre-commit/pre-commit-hooks')
    'github.com/pre-commit/pre-commit-hooks'

    >>> normalize_repo('https://github.com:pre-commit/pre-commit-hooks')
    'github.com/pre-commit/pre-commit-hooks'

    >>> normalize_repo('https://chriskuehl:password@github.com:pre-commit/pre-commit-hooks')
    'github.com/pre-commit/pre-commit-hooks'
    """
    if '//' in path:
        path = path[path.index('//') + 2:]
    if '@' in path:
        path = path[path.index('@') + 1:]
    path = path.replace(':', '/', 1)
    return path


@cached('hook_users.json')
def hook_users(repos):
    hooks = defaultdict(set)
    for i, (repo, url) in enumerate(repos.items()):
        # TODO: this isn't foolproof
        url = url.replace('https://github.com/', 'https://raw.github.com/')
        url = url.replace('/blob/', '/')

        req = requests.get(url, allow_redirects=True)
        assert req.status_code == 200, req.status_code

        try:
            conf = yaml.safe_load(req.text)
        except yaml.YAMLError:
            continue
        else:
            if not isinstance(conf, list):
                continue
            for hook_repo in conf:
                if not isinstance(hook_repo, dict):
                    continue
                if 'repo' not in hook_repo or not isinstance(hook_repo['repo'], str):
                    continue
                if 'hooks' not in hook_repo or not isinstance(hook_repo['hooks'], list):
                    continue

                normalized_repo = normalize_repo(hook_repo['repo'])
                for hook in hook_repo['hooks']:
                    if not isinstance(hook, dict):
                        continue
                    if 'id' not in hook or not isinstance(hook['id'], str):
                        continue
                    hooks['{}#{}'.format(normalized_repo, hook['id'])].add(repo)

        print('Progress: {}/{}'.format(i + 1, len(repos)))
    return {key: list(value) for key, value in hooks.items()}


def main():
    # this is almost entirely side effects lol
    repos = all_repos_using_pre_commit()
    hooks = hook_users(repos)

    print('All done!')
    print('Take a look at the shiny new JSON files in your current directory!')
    print()
    print('The most popular hooks are:')
    for hook in sorted(hooks, key=lambda hook: len(hooks[hook]), reverse=True):
        print('{: <4} {}'.format(len(hooks[hook]), hook))


if __name__ == '__main__':
    exit(main())
