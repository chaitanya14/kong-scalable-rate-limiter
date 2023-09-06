#!/bin/bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ '$BRANCH' != 'main' ]; then
  echo "Branch is not main, exiting"
  exit 1
fi
luarocks make
luarocks pack quizizz-scalable-rate-limiter 1.1.0-1
aws s3 cp quizizz-scalable-rate-limiter-1.1.0-1.all.rock s3://lua-plugins-prod
