===================
dbus-broker-session
===================

---------------------------
Launcher for D-Bus Sessions
---------------------------

:Manual section: 1
:Manual group: User Commands

SYNOPSIS
========

| ``dbus-broker-session`` [ OPTIONS ] [--] PROGRAM [ARGUMENTS..]
| ``dbus-broker-session`` ``--version``
| ``dbus-broker-session`` ``--help``


DESCRIPTION
===========

**dbus-broker-session** starts a new D-Bus session instance. By default, it
spawns a new instance of **dbus-broker** as well as a new instance of the
program given on the command-line. The message broker as well as the program
are tracked and if either exits, the other is terminated and
**dbus-broker-session** returns.

**PATH** is searched to find *PROGRAM*, and (unless specified with a path) to
find the message broker.

The address of the session bus is made available to *PROGRAM* in the
environment variable **DBUS_SESSION_BUS_ADDRESS**. The variables
**DBUS_SESSION_BUS_PID**, **DBUS_SESSION_BUS_WINDOWID**,
**DBUS_STARTER_BUS_TYPE**, and **DBUS_STARTER_ADDRESS** are removed from the
environment, if present.

OPTIONS
=======

The following command-line options are supported. If an option is passed, which
is not listed here, the launcher will deny startup and exit with an error.

--help                          print usage information and exit immediately
--version                       print build-version and exit immediately
--config-file=PATH              config file to use (**Default**:
                                */usr/share/dbus-1/session.conf*)
--dbus-broker=EXE, --dbus-daemon=EXE
                                run a message broker by searching for *EXE* in
                                *$PATH* (or invoke *EXE* directly if it is an
                                absolute path); the last option takes
                                precedence (**Default**: search *$PATH* for
                                *dbus-broker-launch*)

EXIT STATUS
===========

**dbus-broker-session** exits with the exit status of *PROGRAM*, 0 if the
`--help` or `--version` options were used, 127 on an error within
**dbus-broker-session** itself, or `128+n` if *PROGRAM* was terminated by
signal `n`.

SEE ALSO
========

``dbus-broker``\(1)
``dbus-broker-launch``\(1)
``dbus-daemon``\(1)
``dbus-launch``\(1)
``dbus-run-session``\(1)
