#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import scoped_session, mapper
from sqlalchemy.orm.session import sessionmaker
import os
import sys

parent = "/".join(sys.path[0].split("/")[:-2])
_default_db_url = 'sqlite:////{}/database.sqlite3'.format(parent)
engine = create_engine(
    os.environ.get("SPYGUARD_DB_URL", _default_db_url), convert_unicode=True)
metadata = MetaData(bind=engine)
session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

class Model(object):
    query = session.query_property()
