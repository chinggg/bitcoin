#!/bin/bash

CORPUS="../qa-assets/fuzz_seed_corpus/process_message_tx"
FUZZ=txorphan lldb -- ./src/test/fuzz/fuzz $CORPUS
