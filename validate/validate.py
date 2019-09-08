import requests
import json
import csv
import os
import uuid
from AppDynamicsREST.appd.request import AppDynamicsClient

# variables
controllerURL = 'http://controller4221bare-ddsrikar-ndca8gxk.srv.ravcloud.com:8090'
accountName = 'customer1'
username = 'admin'
password = 'admin'
application = 'app1'

loginQuery = '/controller/auth?action=login'
errorDetectionRulesQuery = '/controller/restui/applicationManagerUiBean/applicationConfiguration/'


def apply_exceptions_match_rules(pattern):
    ret = False
    matches = ['*.*', 'com.*', 'myErrorMessage']
    match = set([])
    for m in matches:
        if m in pattern:
            match.add(m)
            ret = True
    return ret, match


def apply_logger_match_rules(pattern):
    ret = False
    matches = ['*.*', 'com.*', 'myErrorMessage']
    match = set([])
    for m in matches:
        if m in pattern:
            match.add(m)
            ret = True
    return ret, match


def validate_error_detection_rules(app):
    result = 'Pass'
    problem_regex = ''
    rules = get_error_detection_rules(app.id)
    ignore_exp_match_type = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['extendedMatchType']
    ignore_exp_match_pattern = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['extendedMatchPattern']
    ignore_exp_regex_groups = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['regexGroups']
    print('App Name: %s --- IgnoreExceptions MatchType: %r' % (app.name, ignore_exp_match_type))
    print('App Name: %s --- IgnoreExceptions MatchPattern: %r' % (app.name, ignore_exp_match_pattern))
    print('App Name: %s --- IgnoreExceptions Regex Groups: %r' % (app.name, ignore_exp_regex_groups))
    ignore_logger_match_type = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['extendedMatchType']
    ignore_logger_match_pattern = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['extendedMatchPattern']
    ignore_logger_regex_groups = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['regexGroups']
    print('App Name: %s --- IgnoreLogger MatchType: %r' % (app.name, ignore_logger_match_type))
    print('App Name: %s --- IgnoreLogger MatchPattern: %r' % (app.name, ignore_logger_match_pattern))
    print('App Name: %s --- IgnoreLogger Regex Groups: %r' % (app.name, ignore_logger_regex_groups))
    f = open('results.csv', "a")
    #
    if ignore_exp_match_type == 'REGEX':
        (result1, match1) = apply_exceptions_match_rules(ignore_exp_match_pattern)
        if result1:
            result = 'Fail'
            # problem_regex = next(iter(match1), set())
            problem_regex = str(match1)

        print ("%r --- %r" % (result1, match1))
    if ignore_logger_match_type == 'REGEX':
        (result2, match2) = apply_logger_match_rules(ignore_logger_match_pattern)
        if result2:
            result = 'Fail'
            # problem_regex = problem_regex + ", " + next(iter(match2), set())
            problem_regex = str(match2) + " - " + problem_regex
        print ("%r ::: %r" % (result2, match2))
    f.write("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s \n" % (
        result, problem_regex, controllerURL, app.name, ignore_exp_match_type, ignore_exp_match_pattern, ignore_exp_regex_groups,
        ignore_logger_match_type, ignore_logger_match_pattern, ignore_logger_regex_groups))
    f.close()


def read_controller_info(row):
    values = []
    count = 0
    for col in row:
        if count == 0:
            controllerURL = col
        # print("%10s"%col)
        if count == 1:
            accountName = col
        # print("%10s"%col)
        if count == 2:
            username = col
        # print("%10s"%col)
        if count == 3:
            password = col
        # print("%10s"%col)
        if count == 4:
            application = col
        # print("%10s"%col)

def get_appdynamics_client():
    cli = AppDynamicsClient(controllerURL, username, password, accountName)
    return cli

def generate_controller_api_session():
    user = username + '@' + accountName
    response = requests.get(controllerURL + loginQuery, auth=(user, password))
    # print(response.cookies)
    for c in response.cookies:
        if c.name == 'JSESSIONID':
            JSESSIONID = c.value
        # print(JSESSIONID)
        if c.name == 'X-CSRF-TOKEN':
            csrf_token = c.value
        # print(csrf_token)
    cookies = {
        'JSESSIONID': JSESSIONID,
    }

    headers = {
        'X-CSRF-TOKEN': csrf_token,
    }
    return headers, cookies

def get_error_detection_rules(app_id):
    url = '{0}{1}{2}'.format(controllerURL, errorDetectionRulesQuery, app_id)
    headers, cookies = generate_controller_api_session()
    res = requests.get(url, headers=headers, cookies=cookies)
    rules = json.loads(res.text)
    return rules

def start():
    # Controller input file name
    controller_list = "default.csv"
    output_filename = "results.csv"

    if os.path.exists(output_filename):
        os.remove(output_filename)
    results_file = open(output_filename, "w")
    results_file.write(
        "Result, Problem Regex, Controller, Application, ignore_exp_match_type, ignore_exp_match_pattern, ignore_exp_regex_groups, "
        "ignore_logger_match_type, ignore_logger_match_pattern, ignore_logger_regex_groups \n")
    results_file.close()

    # initializing the titles and rows list
    rows = []

    # reading csv file
    with open(controller_list, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        next(csvreader)
        for row in csvreader:
            read_controller_info(row)
            cli = get_appdynamics_client()
            for app in cli.get_applications():
                print("App Name -- %s,  App Id -- %s" % (app.name, app.id))
                validate_error_detection_rules(app)


if __name__ == '__main__':
    start()

