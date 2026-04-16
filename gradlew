#!/bin/bash

#
# Gradle wrapper script for SecureBitchat Android
#

# Resolve project root
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Use gradle wrapper if available, otherwise gradle
if [ -f "$PROJECT_ROOT/gradlew" ]; then
    exec "$PROJECT_ROOT/gradlew" "$@"
else
    exec gradle "$@"
fi
