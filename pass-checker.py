# ------------------------------------------------------------------------------------------------------------------
# demonstrates a password checker which takes the passwords as input through the command line and
# provides an output mentioning the number of times the passwords has been breached or not
# 
# K-Anonymity technique has been used in this case and the API used is provided by https://haveibeenpwned.com/API/v3
#
# ------------------------------------------------------------------------------------------------------------------
import requests
import hashlib
import sys


def request_api_data(query_char):
    """
    This function sends a request to the API and returns the response 
    if the response code is 200, else it will raise a RunTime Error
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching : {res.status_code}, check the api and try again')
    return res


def read_response(hashes, tail_hash_to_check):
    """
    The function compares the password provided as input with the response received from the API
    and returns the breach count
    """
    hashes = (h.split(':') for h in hashes.text.splitlines())
    for hash_tail, count_hash_tail_breached in hashes:
        if hash_tail == tail_hash_to_check:
            return count_hash_tail_breached
    return 0


def response_checker(password):
    """
    This function makes the password go through the SHA1 hashing technique 
    and returns the hashed password which is then split into head = first five characters of the hashed string, tail
    The tail is sent to another function for comparison
    """
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # converting the password first requires conversion to 
    first5_chars, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_chars)
    return read_response(response, tail)


def main(args):
    """
    main function
    """
    for password in args:
        cnt = response_checker(password)
        if cnt:
            print(f'{password} was found {cnt} times!!!\nYou should consider changing the password right away\n')
        else:
            print(f'{password} was not breached!!\n')


if __name__ == "__main__":
    main(sys.argv[1:])