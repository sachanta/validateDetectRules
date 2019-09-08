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

resp = c.get_audit_history('2017-04-27T08:00:00.000-0800', '2017-04-27T20:00:00.000-0800')

for audit in resp.by_user_name("user1"):
    print(audit)
for audit in resp.by_action("LOGIN"):
    print(audit)
for audit in resp.by_account_name("customer1"):
    print(audit)
