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

account = c.get_my_account()

action = {'name': 'suppress',
          'timeRange': {'startTimeMillis': '2017-03-24T16:16:57+0000',
                        'endTimeMillis': '2017-10-25T04:16:57+0000'},
          'heathRuleIds': '1,2,3',
          'affects': {'type': 'APP'}}
resp = c.create_action_suppression(account.id, app_id=16, params=action)
print(resp)

resp = c.get_action_suppressions(account.id, app_id=16)
print(resp)

id = resp.actionSuppressions[0].id
resp = c.get_action_suppression(account.id, app_id=16, action_suppression_id=id)
print(resp)

resp = c.delete_action_suppression(account.id, app_id=16, action_suppression_id=id)
print(resp)
