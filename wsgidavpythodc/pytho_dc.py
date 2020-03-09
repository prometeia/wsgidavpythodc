import time
import six
import requests
from os.path import dirname
from wsgidav.dc.base_dc import BaseDomainController
from wsgidav.util import get_module_logger
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN, HTTP_METHOD_NOT_ALLOWED

_log = get_module_logger("pytho_dc")


def expiring_lru_cache(maxsize=128, timeout=60):

    if six.PY2:
        from repoze.lru import lru_cache as lru_cache_py2
        return lru_cache_py2(maxsize=maxsize, timeout=timeout)

    if six.PY3:
        from functools import lru_cache, wraps

        def py3_lru_cache(func):
            lru_cache(maxsize=maxsize)
            def cachedfunc(*args, **kwds):
                del kwds['_ttl_hash']
                return func(*args, **kwds)

            wraps(func)
            def wrapper(*args, **kwds):
                # the same value withing <timeout> time period.
                ttl_hash = int(time.time()) // timeout
                return cachedfunc(*args, _ttl_hash=ttl_hash, **kwds)

            return wrapper

        return py3_lru_cache


class FailedPythoAuth(Exception):
    errcode = 400


class PAUnauthenticated(FailedPythoAuth):
    errcode = 401


class PAUnauthorized(FailedPythoAuth):
    errcode = 403


@expiring_lru_cache()
def _pytho_rest_req(method, url, ba=None, ticket=None, timeout=60):
    _log.debug("Pytho request %s %s", method, url)
    try:
        ret = requests.request(method=method, url=url, timeout=timeout, auth=ba,
                               headers=dict(ticket) if ticket else dict())
    except (requests.ConnectionError, requests.exceptions.ReadTimeout):
        _log.exception("PythoAuth connection error")
        raise FailedPythoAuth("Failed PythoAuth connection {}",format(method))
    if ret.status_code // 100 not in [2, 4] or not ret.text.strip():
        raise FailedPythoAuth(
            "Failed PythoAuth with request {} {} cause unexpected response, code {} body {}".format(
            method, url, ret.status_code, ret.text.strip()
        ))
    if not ret.status_code // 100 == 2:
        _log.warning("Unauthorized request %s %s with status code %s", method, url, ret.status_code)
        return
    return ret


def destination_parse(uri, realm):
    if not uri:
        return
    pathpp = six.moves.urllib.parse.urlparse(uri).path.split('/')
    if pathpp[:2] != realm.split('/'):
        raise DAVError(HTTP_FORBIDDEN, "Forbidden destination realm '{}'")
    return '/' + '/'.join(pathpp[2:])


class PythoDomainController(BaseDomainController):
    CONFIG_KEY = "pytho_dc"
    SUPERUSER_ROLE = "superuser"

    def __init__(self, wsgidav_app, config):
        super(PythoDomainController, self).__init__(wsgidav_app, config)
        dc_conf = config.get(self.CONFIG_KEY, {})
        self.pauri = (dc_conf.get("uri") or "").rstrip('/')
        if not self.pauri:
            raise RuntimeError("Missing or empty option: {}.auth_service_uri".format(self.CONFIG_KEY))
        self.patimeout = dc_conf.get("timeout", 15)
        self.ticketkey = dc_conf.get("ticketkey", "doob-tkt")
        self.baserealm = dc_conf.get("baserealm", '/ufsa').rstrip('/')
        self.superadmin = dc_conf.get("superadmin", False)

    def _pytho_req(self, method, resource, retjson=False, ba=None, ticket=None):
        url = self.pauri + '/api/v0/' + resource
        tkt = (self.ticketkey, ticket) if ticket else None
        ret = _pytho_rest_req(method, url, timeout=self.patimeout, ba=ba, ticket=tkt)
        if ret is None:
            return
        if retjson:
            return ret.json()
        return ret.text.strip()

    def _get_user_info(self, username, ba=None, ticket=None):
        return self._pytho_req('GET', 'users/{}'.format(username), retjson=True, ba=ba, ticket=ticket)

    def _create_ticket(self, username, password):
        return self._pytho_req('POST', 'auth', ba=(username, password))

    # ABC Implementation

    def get_domain_realm(self, path_info, environ):
        """Resolve a relative url to the appropriate realm name."""
        realm = self._calc_realm_from_path_provider(path_info, environ)
        return realm

    def require_authentication(self, realm, environ):
        # Everything authenticated
        return realm != "/:dir_browser"

    def basic_auth_user(self, realm, user_name, password, environ):
        if realm != self.baserealm:
            raise DAVError(HTTP_FORBIDDEN, "Forbidden access to realm '{}'".format(realm))
        user = self._get_user_info(user_name, ba=(user_name, password))
        ok = bool(user and isinstance(user, dict) and user.get('is_active'))
        if ok:
            user_dir = '/' + user.get('user_dir').rstrip('/')
            respath = environ['PATH_INFO']
            tgpath = destination_parse(environ.get('HTTP_DESTINATION'), realm)
            method = environ['REQUEST_METHOD']
            roles = set(user.get("roles", ["reader"]))
            if user.get('is_superuser'):
                roles.add("admin")
            if dirname(respath) == user_dir:
                roles.add("editor")
            is_superadmin = "admin" in roles and superadmin

            if not is_superadmin and user_dir not in (dirname(respath), respath):
                raise DAVError(HTTP_FORBIDDEN, "Forbidden access to '{}'".format(respath))
            if not is_superadmin and tgpath and dirname(tgpath) != user_dir:
                raise DAVError(HTTP_FORBIDDEN, "Forbidden access to '{}'".format(tgpath))
            if not is_superadmin and method == 'MKCOL':
                raise DAVError(HTTP_METHOD_NOT_ALLOWED,
                               "Not allowed on resource '{}' method '{}'".format(path, method))
            environ["wsgidav.auth.roles"] = roles
            environ["wsgidav.auth.user_dir"] = user_dir
        return ok

    def supports_http_digest_auth(self):
        return False
