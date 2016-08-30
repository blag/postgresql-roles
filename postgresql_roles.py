import re

POSTGRESQL_PRIVILEGES = {
    'r': "SELECT (read)",
    'w': "UPDATE (write)",
    'a': "INSERT (append)",
    'd': "DELETE",
    'D': "TRUNCATE",
    'x': "REFERENCES",
    't': "TRIGGER",
    'X': "EXECUTE",
    'U': "USAGE",
    'C': "CREATE",
    'c': "CONNECT",
    'T': "TEMPORARY",
    # 'arwdDxt': "ALL PRIVILEGES (for tables, varies for other objects)",
    '*': "grant option for preceding privilege",
}


class PostgresqlPrivilege(object):
    abbr = ''

    def __init__(self, abbr, *args, **kwargs):
        if abbr not in POSTGRESQL_PRIVILEGES:
            raise Exception(
                "PostgreSQL privileges must be one of [{}], not '{}'".format(
                    ''.join(POSTGRESQL_PRIVILEGES), abbr))

        self.abbr = abbr

    def __str__(self):
        return self.abbr

    def _get_name(self):
        return POSTGRESQL_PRIVILEGES[self.abbr]

    name = property(_get_name)


class PostgresqlPrivilegeList(object):
    _list = []

    def __init__(self, privs, *args, **kwargs):
        if privs.__class__ == PostgresqlPrivilegeList:
            self._list = privs._list
        elif privs.__class__ == str or privs.__class__ == list:
            self._list = [PostgresqlPrivilege(_) for _ in privs]
        else:
            raise Exception("You must initialize PostgresqlPrivilegeList with "
                            "a str, list, or another PostgresqlPrivilegeList")

    def __str__(self):
        return ''.join([str(priv) for priv in self._list])

    def append(self, obj):
        if obj.__class__ == PostgresqlPrivilege:
            _obj = obj
        else:
            _obj = PostgresqlPrivilege(obj)

        self._list = {x.abbr: x for x in self._list.append(obj)}.values()

    def clear(self):
        self._list.clear()

    def copy(self):
        return self._list.copy()

    def extend(self, _obj):
        if _obj.__class__ == PostgresqlPrivilegeList:
            self._list = {x.abbr: x for x in self._list.extend(_obj._list)}.values()
        else:
            raise Exception("You can only extend a PostgresqlPrivilegeList "
                            "with another PostgresqlPrivilegeList")

    def index(self, obj):
        return self._list.index(obj)

    def insert(self, idx, obj):
        if obj.__class__ == PostgresqlPrivilege:
            _obj = obj
        else:
            _obj = PostgresqlPrivilege(obj)

        self._list = {x.abbr: x for x in self._list.insert(idx, obj)}.values()

    def pop(self, i=None):
        if i is None:
            self._list.pop()
        else:
            self._list.pop(i)

    def remove(self, obj):
        self._list.remove(obj)

    def reverse(self):
        self._list = self._list.reverse()

    def sort(self, cmp=None, key=None, reverse=False):
        self._list = self._list.sort(cmp=cmp, key=key, reverse=reverse)


class PostgresqlRole(object):
    name = ''
    _privileges = []
    granted_by_name = ''
    granted_by = None

    def __init__(self, role_str=None, *args, **kwargs):
        if role_str is not None:
            role_name, role_attrs = role_str.split('=')
            if not role_name:
                self.name = 'PUBLIC'
            else:
                self.name = role_name

            attrs, granter = role_attrs.split('/')

            self.privileges = attrs

            self.granted_by_name = granter
        else:
            self.name = kwargs.get('name', '') or 'PUBLIC'

            self.privileges = kwargs.get('privs')

            granted_by = kwargs.get('granted_by', None)

            if granted_by.__class__ == str:
                self.granted_by_name = granted_by
            else:
                self.granted_by = granted_by

            if not self.granted_by_name:
                if self.granted_by:
                    self.granted_by_name = self.granted_by.name
                elif 'granted_by_name' in kwargs:
                    self.granted_by_name = kwargs['granted_by_name']
                else:
                    raise Exception("You must specify 'granted_by' or "
                                    "'granted_by_name' to PostgresqlRole")

    def __str__(self):
        return '{}={}/{}'.format(
            '' if self.name == 'PUBLIC' else self.name,
            self.privileges,
            self.granted_by if self.granted_by else self.granted_by_name)

    def _get_privileges(self):
        return self._privileges

    def _set_privileges(self, privs):
        if privs.__class__ == PostgresqlPrivilegeList:
            self._privileges = privs
        else:
            self._privileges = PostgresqlPrivilegeList(list(privs))

    privileges = property(_get_privileges, _set_privileges)


class PostgresqlRoleList(object):
    _list = []

    def __init__(self, roles, *args, **kwargs):
        self._list = [PostgresqlRole(_.strip()) for _ in re.split(r'\n|,', roles) if _.strip()]

    def __str__(self):
        return '\n'.join([str(_) for _ in self._list])

    def append(self, obj):
        if obj.__class__ == PostgresqlRole:
            _obj = obj
        else:
            _obj = PostgresqlRole(obj)

        self._list = {x.abbr: x for x in self._list.append(obj)}.values()

    def clear(self):
        self._list.clear()

    def copy(self):
        return self._list.copy()

    def extend(self, _obj):
        if _obj.__class__ == PostgresqlRoleList:
            self._list = {x.abbr: x for x in self._list.extend(_obj._list)}.values()
        else:
            raise Exception("You can only extend a PostgresqlRoleList with "
                            "another PostgresqlRoleList")

    def index(self, obj):
        return self._list.index(obj)

    def insert(self, idx, obj):
        if obj.__class__ == PostgresqlRole:
            _obj = obj
        else:
            _obj = PostgresqlRole(obj)

        self._list = {x.abbr: x for x in self._list.insert(idx, obj)}.values()

    def pop(self, i=None):
        if i is None:
            self._list.pop()
        else:
            self._list.pop(i)

    def remove(self, obj):
        self._list.remove(obj)

    def reverse(self):
        self._list = self._list.reverse()

    def sort(self, cmp=None, key=None, reverse=False):
        self._list = self._list.sort(cmp=cmp, key=key, reverse=reverse)


if __name__ == '__main__':
    roles = """
        miriam=arwdDxt/miriam
        =r/miriam,admin=arw/miriam
        george=ra/miriam,    root=rwadDxtXUCcT/admin
    """

    cleaned_roles = '\n'.join([_.strip() for _ in """
        miriam=arwdDxt/miriam
        =r/miriam
        admin=arw/miriam
        george=ra/miriam
        root=rwadDxtXUCcT/admin
    """.split('\n') if _.strip()])

    for p in 'rwadDxtXUCcT':
        assert p == str(PostgresqlPrivilege(p))
        assert PostgresqlPrivilege(p).name == POSTGRESQL_PRIVILEGES[p]

    assert 'rwadDxtXUCcT' == str(PostgresqlPrivilegeList('rwadDxtXUCcT'))

    assert 'miriam=arwdDxt/miriam' == str(PostgresqlRole('miriam=arwdDxt/miriam'))

    assert '=r/miriam' == str(PostgresqlRole('=r/miriam'))

    assert 'PUBLIC' == PostgresqlRole('=r/miriam').name
    assert 'miriam' == PostgresqlRole('=r/miriam').granted_by_name

    assert '=r/miriam' == str(PostgresqlRole(name='', privs='r', granted_by='miriam'))
    assert 'PUBLIC' == PostgresqlRole(name='', privs='r', granted_by='miriam').name
    assert 'miriam' == PostgresqlRole(name='', privs='r', granted_by='miriam').granted_by_name

    assert cleaned_roles == str(PostgresqlRoleList(roles))
