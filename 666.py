# -*- coding: utf-8 -*-
__author__ = "fengliang"

import datetime
from app import app
import jwt
from jwt import PyJWT
import uuid
from calendar import timegm

py_jwt = PyJWT()

now = datetime.datetime.utcnow()

token_data = {
    'iat': now,
    'nbf': now,
    'jti': str(uuid.uuid4()),
}

token_data['exp'] = now + datetime.timedelta(minutes=2)
token_data.update({
        'rosefinch': '123',
        'fresh': False,
        'type': 'access',
        'user-client': '123',
    })

# print(py_jwt.encode(token_data, key='super-secret', algorithm='HS256', json_encoder=app.json_encoder).decode('utf-8'))



def judge_expire(token_info):
    now = timegm(datetime.datetime.utcnow().utctimetuple())
    if token_info['exp'] < now:
        print('has expired')
    else:
        print('useful')


if __name__ == "__main__":
    info = py_jwt.decode(jwt="eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLWNsaWVudCI6eyJyb2xlIjoiMSJ9LCJqdGkiOiJmM2NlOGQ3ZC0wMDEzLTRhNDItYmVmNS04MTAzMzQwZmI3YzEiLCJleHAiOjE1NTIzNzc2NjMsImZyZXNoIjpmYWxzZSwicm9zZWZpbmNoIjoibXVzZXIiLCJpYXQiOjE1NTE5NDU2NjMsInR5cGUiOiJhY2Nlc3MiLCJuYmYiOjE1NTE5NDU2NjN9.oBVKPqMR0WQsZBWd1QFyf3-2AMOQVdU3DbjphsjUVL9yRS6QcqJ1UEVJDNu5ebVV5PJkKAL_-1t4R5D-D3PDdGU96KniwRHtk1mH8PApo8R4vUB0f3XkhrUoG8szHiG6jF_vRAJU4rkU6djOzxpszAVuXDqKlomvz0ij9Gu970yRPyC_OEC1fDnwhXnbt7534Kil8gwo9pjoDDkTsjx6-O3vE-tSFH0Heyx6nMffYEj2ZuzDShVzEORmK7R4XTeZLZ6QLc8UquAMR4AnDrtFJKwWcVit15Qituo84gVF7Mvqzi26nuv3EyQYXCHow8MKUkVjMnGIvbeqj63p_MSq7g",
                    verify=False)
    print(info)
    # judge_expire(token_info=info)
    # import IPy
    # print('192.168.1.0' in IPy.IP('192.168.24.0-192.168.24.20'))
    # start_time = datetime.datetime.strptime(date_string="2019-1-17 14:20:30", format="%H:%M:%S")
    # end_time = datetime.datetime.strptime(date_string="2019-1-17 16:30:30", format="%H:%M:%S")

    # now = datetime.datetime.now().isoweekday()
    # print(type(now))

    # if now > start_time and now < end_time:
    #     print('in range')
