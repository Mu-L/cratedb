.. _ref-show-tables:

===============
``SHOW TABLES``
===============

Lists the tables in the database.

Synopsis
========

::

    SHOW TABLES [{FROM | IN} table_schema] [LIKE 'pattern' | WHERE expression]

Description
===========

``SHOW TABLES`` can be used to retrieve the table names of the database in
alphabetical order. The same list can be fetched by querying table names of the
``information_schema.tables`` table.

System and BLOB tables are only listed when they are explicitly specified in
``FROM | IN`` clause.

Parameters
==========

:table_schema:
  The name of the schema the tables are appropriate to.

Clauses
=======

``LIKE``
--------

The optional ``LIKE`` clause matches only on table names and omits schema
names. It takes a string pattern as a filter and has an equivalent behavior to
:ref:`sql_dql_like`.

``WHERE``
---------

The optional WHERE clause defines the condition to be met for a row to be
returned.
