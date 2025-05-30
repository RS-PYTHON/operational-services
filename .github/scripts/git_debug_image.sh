#!/usr/bin/env bash
# Copyright 2024 CS Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Git clone the repository in the Docker image to be able to modify and debug it from the deployed pod.
# This script is run from the ci/cd.

set -euo pipefail
# set -x

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR="$(realpath $SCRIPT_DIR/..)"

# Read input arguments
BRANCH_NAME="$1" # git branch name

# Install components in the docker images
apt update
apt install -y git vim emacs-nox nano

# Add aliases to bash
cat << EOF >> /home/user/.bashrc
alias ll='ls -alFh'
alias ls='ls --color=auto'
EOF

# Git clone the project branch with HTTP authentication so we don't need any
# ssh key to pull the rspy repository, which is public.
# To be discussed: how to push to the repo ? I guess we would need a ssh key
# in the pod but I'm not sure it would be secure.
cd /home/user
git clone -b "$BRANCH_NAME" https://github.com/RS-PYTHON/operational-services.git
cd ./operational-services

# The rspy modules used by the fastapi service are installed under /usr/local/lib/python3.11/site-packages
# We tell the service to use the git dirs instead. So we replace them by symlinks to git.
py_site_packages=$(python -c "import site; print(site.getsitepackages()[0])")
for git_pydir in $(pwd)/object_storage_access_manager/osam; do
    pydir=$(basename "$git_pydir")
    if [ -d "$py_site_packages/$pydir" ]; then
        (set -x; cd "$py_site_packages" && rm -rf "$pydir" && ln -s "$git_pydir" .)
    fi
done

# Owner = the docker image user
chown -R user:user /home/user/operational-services

# Clean everything
rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*
