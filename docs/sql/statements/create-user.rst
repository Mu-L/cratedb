.. highlight:: psql
.. _ref-create-user:

===============
``CREATE USER``
===============

Create a new database user.

Synopsis
========

.. code-block:: psql

  CREATE USER username
  [ WITH ( user_parameter = value [, ...]) ] |
  [ [ WITH ] user_parameter [value] [ ... ] ]

Description
===========

``CREATE USER`` is a management statement to create a new database user in the
CrateDB cluster. The newly created user does not have any special privileges,
and those must be assigned afterwards, for details see the
:ref:`privileges documentation<administration-privileges>`.
The created user can be used to authenticate against CrateDB, see
:ref:`admin_hba`.

The statement allows to specify a password for this account. This is not
necessary if password authentication is disabled.

.. NOTE::

    ``USER`` is essentially the same as ``ROLE`` with the difference that a
    ``USER`` **can** login to the database and **can** also be assigned a
    password, but **cannot** be granted to another ``USER`` or ``ROLE``. On the
    contrary, a ``ROLE`` **cannot** login to the database, and therefore
    **cannot** be assigned a password, but it **can** be
    :ref:`granted <granting_roles>` to another ``USER`` or ``ROLE``.

For usages of the ``CREATE USER`` statement see
:ref:`administration_user_management`.

Parameters
==========

:username:
  The unique name of the database user.

  The name follows the principles of a SQL identifier (see
  :ref:`sql_lexical_keywords_identifiers`).

Clauses
=======

``WITH``
--------

The following ``user_parameter`` are supported to define a new user account:

:password:
  The password as cleartext entered as string literal. e.g.::

     CREATE USER john WITH (password='foo')

  ::

     CREATE USER john WITH password='foo'

  ::

     CREATE USER john WITH password 'foo'

  ::

     CREATE USER john password 'foo'

.. vale off

.. _create-user-jwt:

:jwt:
  JWT properties map ('iss', 'username' and 'aud') entered as string literal. e.g.::

     CREATE USER john WITH (jwt = {"iss" = 'https://example.com', "username" = 'test@example.com', "aud" = 'test_aud'})

  `iss`_ is a JWK endpoint, containing public keys. Required field.

  ``username`` is a user name in a third party app. Required field.

  `aud`_ is a recipient that the JWT is intended for. Optional field. If not provided, the cluster id is used (default).

  Combination of ``iss`` and ``username`` must be unique.

.. WARNING::

    If :ref:`auth.host_based.jwt.iss <auth.host_based.jwt.iss>` is set,
    user specific properties are ignored and :ref:`jwt_defaults` are used.

.. SEEALSO::

  :ref:`auth_jwt`

.. vale on

.. _iss: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
.. _aud: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
