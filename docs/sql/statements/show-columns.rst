.. _ref-show-columns:

================
``SHOW COLUMNS``
================

``SHOW COLUMNS`` displays information about columns in a given table.

Synopsis
========

::

    SHOW COLUMNS { FROM | IN } table_name [ FROM | IN table_schema ] [ LIKE 'pattern' | WHERE expression ]

Description
===========

``SHOW COLUMNS`` fetches all column names of a given table and displays their
column name and data type. The column names are listed in alphabetical order.
More details can be fetched by querying the ``information_schema.columns``
table.

Parameters
==========

:table_name:
  The name of the table of which the column information is printed.

:table_schema:
  The name of the schema the tables are appropriate to.

  If no schema name is specified the default schema is set to ``doc``.

Clauses
=======

``LIKE``
--------

The optional ``LIKE`` clause indicates which column names to match. It takes a
string pattern as a filter and has an equivalent behavior to
:ref:`sql_dql_like`.

``WHERE``
---------

The optional WHERE clause defines the condition to be met for a row to be
returned.
