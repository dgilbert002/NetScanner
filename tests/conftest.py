"""Test fixtures: a throwaway SQLite database and an app that never captures."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Must be set before src.main is imported: no capture threads, temp database.
_TMP_DB = os.path.join(tempfile.mkdtemp(prefix='netscanner-test-'), 'test.db')
os.environ['NETSCANNER_DB_URI'] = f'sqlite:///{_TMP_DB}'
os.environ['NETSCANNER_INTEL'] = '1'
os.environ['NETSCANNER_INTEL_CAPTURE'] = '0'


@pytest.fixture(scope='session')
def app():
    from src.main import app as flask_app
    flask_app.config['TESTING'] = True
    with flask_app.app_context():
        from src.models.user import db
        db.create_all()
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield


@pytest.fixture(scope='session')
def engine(app):
    from src.main import INTEL_ENGINE
    if INTEL_ENGINE is None:
        from src.intel.engine import IntelEngine
        engine = IntelEngine(app=app)
        engine.writer.start()
        return engine
    return INTEL_ENGINE
