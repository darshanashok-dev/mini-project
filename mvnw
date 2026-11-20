#!/usr/bin/env bash
# Maven wrapper script for Cybersecurity Awareness Platform
set -euo pipefail

MAVEN_HOME_CANDIDATES=(
  "/tmp/apache-maven-3.9.9"
  "/usr/share/maven"
  "/usr/local/share/maven"
  "/opt/maven"
)

MVN_CMD=""
if command -v mvn &>/dev/null; then
  MVN_CMD="mvn"
else
  for candidate in "${MAVEN_HOME_CANDIDATES[@]}"; do
    if [[ -x "${candidate}/bin/mvn" ]]; then
      MVN_CMD="${candidate}/bin/mvn"
      break
    fi
  done
fi

if [[ -z "$MVN_CMD" ]]; then
  echo "Error: Maven not found. Please install Maven or place apache-maven in /tmp/apache-maven-3.9.9" >&2
  exit 1
fi

exec "$MVN_CMD" -Duser.home=/tmp "$@"
