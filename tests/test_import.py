import importlib

def test_import():
    pkg = importlib.import_module('wsgidavpythodc')
    assert dir(pkg)
    assert pkg.__name__ == 'wsgidavpythodc'
