import requests
import logging
import logging.handlers
import json
import csv
import os
import sys
import uuid

import funcy
import base64
import Crypto.Protocol
from Crypto.Cipher import AES

from AppDynamicsREST.appd.request import AppDynamicsClient

# variables
#controllerURL = 'http://controller4221bare-ddsrikar-ndca8gxk.srv.ravcloud.com:8090'
#accountName = 'customer1'
#username = 'admin'
#password = 'admin'
#application = 'app1'

loginQuery = '/controller/auth?action=login'
errorDetectionRulesQuery = '/controller/restui/applicationManagerUiBean/applicationConfiguration/'

handler = logging.handlers.WatchedFileHandler(os.environ.get("LOGFILE", "./validateDetectRules.log"))
formatter = logging.Formatter(logging.BASIC_FORMAT)
handler.setFormatter(formatter)
root = logging.getLogger()
root.setLevel(os.environ.get("LOGLEVEL", "INFO"))
root.addHandler(handler)


def decrypt_file(file_name, encrypt_key):
    if isinstance(file_name, str) and isinstance(encrypt_key, str):
        print ("Decrypting the file ...")
    else:
        print("Argument to decrpyt_file function is incorrect. Aborting the program!")
        sys.exit(0)

    with open(file_name, "rb") as encryptedFile:
        chunk_size = 24 * 1024
        encrypted = base64.b64decode(encryptedFile.read(64))
        setup = encrypted[:48]
        # key_confirm = input("Please enter the key used to encrypt the file:- ")
        salt = b'\x9aX\x10\xa6^\x1fUVu\xc0\xa2\xc8\xff\xceOV'
        key_check = Crypto.Protocol.KDF.PBKDF2(password=encrypt_key, salt=salt, dkLen=32, count=10000)

        def unpad(s):
            return s[:-ord(s[len(s) - 1:])]

        if key_check == setup[:32]:
            print("Password Correct!")
        else:
            print("Wrong Password!")
            sys.exit(0)

        iv = setup[32:]
        cipher = AES.new(key_check, AES.MODE_CBC, iv)
        with open('controllers.csv', "wb") as decryptedFile:
            encrypted = base64.b64decode(encryptedFile.read())
            chunks = list(funcy.chunks(chunk_size, encrypted))
            for chunk in chunks:
                decrypted_chunk = unpad(cipher.decrypt(chunk))
                decryptedFile.write(decrypted_chunk)


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


def validate_error_detection_rules(controller_url, username, password, account_name, app):
    result = 'Pass'
    problem_regex = ''
    rules = get_error_detection_rules(controller_url, username, password, account_name, app.id)
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
        result, problem_regex, controller_url, app.name, ignore_exp_match_type, ignore_exp_match_pattern, ignore_exp_regex_groups,
        ignore_logger_match_type, ignore_logger_match_pattern, ignore_logger_regex_groups))
    f.close()


def read_controller_info(row):
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
    res = requests.get(url, headers=headers, cookies=cookies)
    rules = json.loads(res.text)
    return rules


def start():
    logging.info("Starting the program...")
    output_filename = "results.csv"
    controller_list = 'controllers.csv'
    encrypted_controller_list = input("Enter the encrypted file name: ")

    if os.path.exists(encrypted_controller_list):
        print("Reading the file ...\n Output file name is %s" % output_filename)
    else:
        print("File does not exist. Trying to read the default file: 'controllers.csv.aes")
        if os.path.exists("controllers.csv.aes"):
            print("Reading the default file - 'controllers.csv.aes' ... \n Output file name is %s" % output_filename)
            encrypted_controller_list = 'controllers.csv.aes'
        else:
            print("Default file 'controllers.csv.aes' does not exist. Aborting the program!")
            sys.exit(0)
    secret = input("Enter the password to decrypt the file: ")

    if os.path.exists(output_filename):
        os.remove(output_filename)
    results_file = open(output_filename, "w")
    results_file.write(
        "Result, Problem Regex, Controller, Application, ignore_exp_match_type, ignore_exp_match_pattern, ignore_exp_regex_groups, "
        "ignore_logger_match_type, ignore_logger_match_pattern, ignore_logger_regex_groups \n")
    results_file.close()

    decrypt_file(encrypted_controller_list, secret)
    # reading csv file
    print os.path.abspath(controller_list)
    with open(controller_list, 'r') as f:
        if sum(1 for line in f) < 2:
            print("Input file - %s - has no controllers listed or file is incorrectly formatted!\n"
                  "Refer to template.csv for correct format.\n Aborting the program!")
            sys.exit(-1)
        else:
            print("Reading the file...")
    with open(controller_list, 'r') as csvfile1:
        # csvfile = cryptoTool.decrypt_filestream(csvfile1, secret)
        csvreader = csv.reader(csvfile1)
        # os.remove(controller_list)
        next(csvreader)
        for row in csvreader:
            controller_url, username, password, account_name = read_controller_info(row)
            cli = get_appdynamics_client(controller_url, username, password, account_name)

            for app in cli.get_applications():
                print("App Name -- %s,  App Id -- %s" % (app.name, app.id))
                validate_error_detection_rules(controller_url, username, password, account_name, app)


# def enc(file_name, password):
#     cryptoTool.encrypt_file(file_name, password)
#
#
# def dec(file_name, password):
#     cryptoTool.decrypt_file(file_name, password)


if __name__ == '__main__':
    start()
    # enc('temp.csv', 'pass')
    # dec('temp.csv.aes', 'pass')

