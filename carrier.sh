#!/bin/bash
RUSTFLAGS=-Awarnings cargo run --quiet --bin carrier -- "$@"
