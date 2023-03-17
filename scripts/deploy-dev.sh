#!/bin/bash

luarocks make
luarocks pack quizizz-scalable-rate-limiter 1.1.0-1
aws s3 cp quizizz-scalable-rate-limiter-1.1.0-1.all.rock s3://lua-plugins-dev
