#!/bin/bash

/opt/proxy/manage.py makemigrations

/opt/proxy/manage.py migrate

python /opt/proxy/manage.py runserver 0:8000