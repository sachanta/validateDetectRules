import requests
import logging
import logging.handlers
import json
import csv
import os
import sys

from fileCrypto import FileCrypto
from AppDynamicsREST.appd.request import AppDynamicsClient


loginQuery = '/controller/auth?action=login'
errorDetectionRulesQuery = '/controller/restui/applicationManagerUiBean/applicationConfiguration/'

handler = logging.handlers.WatchedFileHandler(os.environ.get("LOGFILE", "./validateDetectRules.log"))
formatter = logging.Formatter(logging.BASIC_FORMAT)
handler.setFormatter(formatter)
root = logging.getLogger()
root.setLevel(os.environ.get("LOGLEVEL", "INFO"))
root.addHandler(handler)


def apply_exceptions_match_rules(pattern):
    ret = False
    matches = ['*.*', 'com.*', 'myErrorMessage', '.*']
    match = set([])
    for m in matches:
        if m in pattern:
            match.add(m)
            ret = True
    return ret, match


def apply_logger_match_rules(pattern):
    ret = False
    matches = ['*.*', 'com.*', 'myErrorMessage', '.*']
    match = set([])
    for m in matches:
        if m in pattern:
            match.add(m)
            ret = True
    return ret, match


def validate_error_detection_rules(controller_url, username, password, account_name, app):
    """

    :param controller_url: str - starts with http or https and includes port number, except for default '80' and '443'
    :param username: str - User name to authenticate to the controller with.
    :param password: str - Password for authentication to the controller.
    :param account_name: str - Account name for multi-tenant controllers. For single-tenant controllers, use
                        the default value of "customer1".
    :param app: object - app object containing info of an app
    :return: none
    """
    result = 'Pass'
    problem_regex = ''
    ignore_exp_match_type = ''
    ignore_exp_match_pattern = ''
    ignore_exp_regex_groups = ''
    ignore_logger_match_type = ''
    ignore_logger_match_pattern = ''
    ignore_logger_regex_groups = ''

    rules = get_error_detection_rules(controller_url, username, password, account_name, app.id)
    if rules is None:
        return
    if rules['errorConfig']['ignoreExceptionMsgPatterns']:
        ignore_exp_match_type = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['extendedMatchType']
    if rules['errorConfig']['ignoreExceptionMsgPatterns']:
        ignore_exp_match_pattern = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['extendedMatchPattern']
    if rules['errorConfig']['ignoreExceptionMsgPatterns']:
        ignore_exp_regex_groups = rules['errorConfig']['ignoreExceptionMsgPatterns'][0]['regexGroups']
    if rules['errorConfig']['ignoreLoggerMsgPatterns']:
        ignore_logger_match_type = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['extendedMatchType']
    if rules['errorConfig']['ignoreLoggerMsgPatterns']:
        ignore_logger_match_pattern = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['extendedMatchPattern']
    if rules['errorConfig']['ignoreLoggerMsgPatterns']:
        ignore_logger_regex_groups = rules['errorConfig']['ignoreLoggerMsgPatterns'][0]['regexGroups']

    f = open('results.csv', "a")
    # csv.writer is used to avoid the issue of incorrect formatting, if the string contains a comma.
    # In csv.writer, strings containing ',' are padded by ""
    results_writer = csv.writer(f)
    if ignore_exp_match_type == 'REGEX':
        (result1, match1) = apply_exceptions_match_rules(ignore_exp_match_pattern)
        if result1:
            result = 'Fail'
            problem_regex = str(match1)
    if ignore_logger_match_type == 'REGEX':
        (result2, match2) = apply_logger_match_rules(ignore_logger_match_pattern)
        if result2:
            result = 'Fail'
            problem_regex = str(match2) + " - " + problem_regex
        print ("%r ::: %r" % (result2, match2))
    if ignore_exp_match_type == 'REGEX' or ignore_logger_match_type == 'REGEX':
        results_writer.writerow((result, problem_regex, controller_url, app.name, ignore_exp_match_type,
                                 ignore_exp_match_pattern, ignore_exp_regex_groups, ignore_logger_match_type,
                                 ignore_logger_match_pattern, ignore_logger_regex_groups))
        f.close()
    else:
        f.close()


def read_controller_info(row):
    """

    :param row: Takes the row from the input file and populates controller fields
    :return: returns controller fields with values
    """
    values = []
    count = 0

    for col in row:
        if count == 0:
            controller_url = col
        # print("%10s"%col)
        if count == 1:
            account_name = col
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
        count += 1
    return controller_url, username, password, account_name


def get_appdynamics_client(controller_url, username, password, account_name):
    cli = AppDynamicsClient(controller_url, username, password, account_name)
    return cli


def generate_controller_api_session(controller_url, username, password, account_name):
    user = username + '@' + account_name
    response = requests.get(controller_url + loginQuery, auth=(user, password))
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


def get_error_detection_rules(controller_url, username, password, account_name, app_id):
    url = '{0}{1}{2}'.format(controller_url, errorDetectionRulesQuery, app_id)
    headers, cookies = generate_controller_api_session(controller_url, username, password, account_name)
    try:
        res = requests.get(url, headers=headers, cookies=cookies)
    except requests.exceptions.RequestException as e:
        logging.error(e)
        return None
    rules = json.loads(res.text)
    return rules


def start():
    """
    This method will read the input file and begins the validation process
    :return:
    """
    logging.info("Starting the program...")
    output_filename = "results.csv"
    controller_list = 'controllers.csv'
    encrypted_controller_list = input("Enter the encrypted file name: ")

    if os.path.exists(encrypted_controller_list):
        print("Reading the file ...\n Output file name is %s" % output_filename)
    else:
        print("File does not exist. Trying to read the default file: 'controllers.csv.aes'")
        if os.path.exists("controllers.csv.aes"):
            print("Reading the default file - 'controllers.csv.aes' ... \n Output file name is %s" % output_filename)
            encrypted_controller_list = 'controllers.csv.aes'
        else:
            print("Default file 'controllers.csv.aes' does not exist. Aborting the program!")
            sys.exit(0)
    secret = input("Enter the password to decrypt the file: ")

    # Writing the headers row to the output file
    if os.path.exists(output_filename):
        os.remove(output_filename)
    results_file = open(output_filename, "w")
    results_file.write(
        "Result, Problem Regex, Controller, Application, ignore_exp_match_type, ignore_exp_match_pattern, ignore_exp_regex_groups, "
        "ignore_logger_match_type, ignore_logger_match_pattern, ignore_logger_regex_groups \n")
    results_file.close()

    fc1 = FileCrypto(encrypted_controller_list, controller_list, secret)
    fc1.decrypt_file()
    print os.path.abspath(controller_list)
    with open(controller_list, 'r') as f:
        if sum(1 for line in f) < 2:
            print("Input file - %s - has no controllers listed or file is incorrectly formatted!\n"
                  "Refer to template.csv for correct format.\n Aborting the program!")
            sys.exit(-1)
        else:
            print("Reading the file...")
    with open(controller_list, 'r') as csvfile1:

        csvreader = csv.reader(csvfile1)
        os.remove(controller_list)
        next(csvreader)
        for row in csvreader:
            if len(row) < 4:
                print ("incomplete controller information: %r" % row)
                break
            controller_url, username, password, account_name = read_controller_info(row)
            # Using the AppDynamicsREST SDK, creating a controller object
            cli = get_appdynamics_client(controller_url, username, password, account_name)
            # Checking if we can login to the controller.
            # If not, then throw an exception and go for next row
            try:
                # Get the list of applications in this controller
                logging.info("Validating the controller - %s" % controller_url)
                cli.get_applications()
                for app in cli.get_applications():
                    logging.info("App Name -- %s" % app.name)
                    validate_error_detection_rules(controller_url, username, password, account_name, app)
            except requests.exceptions.RequestException as e:
                logging.error(e)
                continue


if __name__ == '__main__':
    start()
