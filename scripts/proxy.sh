#!/bin/bash
echo "Setting ABC proxy env vars..."
export http_proxy="http://abc.com:80"
export HTTP_PROXY=$http_proxy
export no_proxy=abc.com
export https_proxy=$http_proxy
export HTTPS_PROXY=$http_proxy
export NO_PROXY=$no_proxy
