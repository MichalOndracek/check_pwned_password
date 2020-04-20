import requests
import hashlib
import sys


def request_api_data(fragment_of_hash_password):
    url = 'https://api.pwnedpasswords.com/range/' + fragment_of_hash_password
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error fetching data: {res.status_code}')
    return res


def get_password_leaks_count(hashes, tail_of_hashed_password):
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == tail_of_hashed_password:
            return count
    return 0


def check_pwned_passwords(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    fragment_of_pass, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(fragment_of_pass)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = check_pwned_passwords(password)

        if count:
            print(f'{password} leaked {count} times')
        else:
            print(f'{password} was never leaked')


main(sys.argv[1:])
