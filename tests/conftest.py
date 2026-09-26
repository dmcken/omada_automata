'''Shared pytest fixtures.

Test fixtures under fixtures/ are the actual JSON shapes confirmed
against a real "Omada Essential" free-tier account (one organization,
two sites), with the account's own IDs/emails/org name replaced by
placeholders since this is a public repository.
'''
import json
import pathlib

import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / 'fixtures'


@pytest.fixture
def load_json():
    '''Factory fixture: load_json('name.json') -> parsed JSON.'''
    def _load(name):
        with open(FIXTURES_DIR / name, encoding='utf-8') as fh:
            return json.load(fh)
    return _load
