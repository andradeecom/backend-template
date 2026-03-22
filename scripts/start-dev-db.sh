#!/bin/bash
set -e

docker-compose --env-file .env.dev -f docker-compose.dev.yml up -d
