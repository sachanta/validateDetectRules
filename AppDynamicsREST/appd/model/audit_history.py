"""
Model classes for AppDynamics REST API

.. moduleauthor:: Kyle Furlong <kyle.furlong@appdynamics.com>
"""

from . import JsonObject, JsonList


class Audit(JsonObject):

    FIELDS = {'timestamp': 'timeStamp', 'account_name': 'accountName',
              'security_provider_type': 'securityProviderType',
              'user_name': 'userName', 'action': 'action'}

    def __init__(self, timestamp=0, account_name=None, security_provider_type=None, user_name=None, action=None):
        (self.timestamp, self.account_name, self.security_provider_type,
         self.user_name, self.action) = (timestamp, account_name, security_provider_type, user_name, action)


class AuditHistory(JsonList):

    def __init__(self, initial_list=None):
        super(AuditHistory, self).__init__(Audit, initial_list)

    def __getitem__(self, i):
        """
        :rtype: Node
        """
        return self.data[i]

    def by_action(self, action):
        """
        Filters an AuditHistory collection to return only the Audits matching the given action.
        :param str name: Action to match against.
        :returns: a AuditHistory collection filtered by action.
        :rtype: AuditHistory
        """
        return AuditHistory([x for x in self.data if x.action == action])

    def by_user_name(self, user_name):
        """
        Filters an AuditHistory collection to return only the Audits matching the given user name.
        :param str name: User name to match against.
        :returns: a AuditHistory collection filtered by user name.
        :rtype: AuditHistory
        """
        return AuditHistory([x for x in self.data if x.user_name == user_name])

    def by_account_name(self, account_name):
        """
        Filters an AuditHistory collection to return only the Audits matching the given account.
        :param str name: Account to match against.
        :returns: a AuditHistory collection filtered by account.
        :rtype: AuditHistory
        """
        return AuditHistory([x for x in self.data if x.account_name == account_name])
