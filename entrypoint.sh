#!/bin/bash

echo $INPUT_APP_PEM | base64 -d > pem.txt
cat pem.txt
echo
python3 ./token_getter.py
