"""
Model classes for AppDynamics REST API

.. moduleauthor:: Kyle Furlong <kyle.furlong@appdynamics.com>
"""

from . import JsonObject, JsonList


class SetControllerUrl(JsonObject):

    FIELDS = {'controllerURL': ''}

    def __init__(self, controllerURL=''):
        (self.controllerURL) = (controllerURL)


class SetControllerUrlResponse(JsonList):

    def __init__(self, initial_list=None):
        super(SetControllerUrlResponse, self).__init__(SetControllerUrl, initial_list)

    def __getitem__(self, i):
        """
        :rtype: Node
        """
        return self.data[i]
