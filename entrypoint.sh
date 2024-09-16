#!/bin/bash

echo 'uProbe running'
gramine-sgx uProbe & 
echo 'uProbe finished'

# Continue with the application
echo 'Running application'
python3 web-server.py