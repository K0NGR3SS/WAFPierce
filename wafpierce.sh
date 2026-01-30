#!/bin/bash
cd "$(dirname "$0")"
python3 -m wafpierce "$1" -t "${2:-10}"