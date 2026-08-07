#!/bin/bash

env SERVER_PORT=8080 \
    PG_CONNECT_STRING='host=localhost port=54321 user=postgres password=password dbname=devdb' \
    USER_ACCOUNT_LIFE=604800 \
    stack run myserve
