"""
Model classes for AppDynamics REST API

.. moduleauthor:: Kyle Furlong <kyle.furlong@appdynamics.com>
"""

from . import JsonObject, JsonList


class ActionSuppression(JsonObject):

    FIELDS = {'id': '',
              'timeRange': '',
              'name': '',
              'affects': ''}

    def __init__(self, id=0, timeRange=None, name='', affects=None):
        (self.id, self.timeRange, self.name, self.affects) = (id, timeRange, name, affects)


class ActionSuppressions(JsonList):

    def __init__(self, initial_list=None):
        super(ActionSuppressions, self).__init__(ActionSuppression, initial_list)

    def __getitem__(self, i):
        """
        :rtype: ActionSuppression
        """
        return self.data[i]


class ActionSuppressionsResponse(JsonObject):

    FIELDS = {}

    def __init__(self):
        self.actionSuppressions = ActionSuppressions()

    @classmethod
    def from_json(cls, json_dict):
        print(json_dict)
        obj = super(ActionSuppressionsResponse, cls).from_json(json_dict)
        if 'actionSuppressions' in json_dict:
            obj.actionSuppressions = ActionSuppressions.from_json(json_dict['actionSuppressions'])
        return obj
