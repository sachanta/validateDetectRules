#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Sample script to print a list of events from the specified controller and app.
"""

from __future__ import print_function

from appd.cmdline import parse_argv
from appd.request import AppDynamicsClient

__author__ = 'Kyle Furlong'
__copyright__ = 'Copyright (c) 2013-2017 AppDynamics Inc.'


args = parse_argv()
c = AppDynamicsClient(args.url, args.username, args.password, args.account, args.verbose)

resp = c.export_entry_point_type(5, 'servlet', 'custom', 'java', 'asdf')
print(resp)
resp = c.import_entry_point_type(5, 'servlet', 'custom', resp, 'java', 'asdf')
print(resp)
