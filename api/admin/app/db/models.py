from sqlalchemy.orm import registry
from app import db

_mapper_registry = registry()


class Ioc(db.Model):
    def __init__(self, value, type, tlp, tag, source, added_on):
        self.value = value
        self.type = type
        self.tlp = tlp
        self.tag = tag
        self.source = source
        self.added_on = added_on


class Whitelist(db.Model):
    def __init__(self, element, type, source, added_on):
        self.element = element
        self.type = type
        self.source = source
        self.added_on = added_on


class MISPInst(db.Model):
    def __init__(self, name, url, key, ssl, added_on, last_sync):
        self.name = name
        self.url = url
        self.apikey = key
        self.verifycert = ssl
        self.added_on = added_on
        self.last_sync = last_sync


class CTIQuarantine(db.Model):
    def __init__(self, name, reason, started_at, duration_days):
        self.name = name
        self.reason = reason
        self.started_at = started_at
        self.duration_days = duration_days


_mapper_registry.map_imperatively(Whitelist, db.Table('whitelist', db.metadata, autoload_with=db.engine))
_mapper_registry.map_imperatively(Ioc, db.Table('iocs', db.metadata, autoload_with=db.engine))
_mapper_registry.map_imperatively(MISPInst, db.Table('misp', db.metadata, autoload_with=db.engine))
_mapper_registry.map_imperatively(CTIQuarantine, db.Table('cti_quarantine', db.metadata, autoload_with=db.engine))
