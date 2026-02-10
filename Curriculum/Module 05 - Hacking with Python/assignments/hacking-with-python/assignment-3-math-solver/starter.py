#!/usr/bin/env python3
"""
Assignment 3: Automated Math Challenge Solver - Starter Code
The Math Gauntlet

Student Name:

Instructions:
- Connect to the challenge server using pwntools.
- Receive and parse math challenges.
- Compute the answers.
- Send back the answers to the server.
- Capture the flag upon successful completion of all challenges.

    Run with: python starter.py
"""

from pwn import remote


# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 9999
CHALLENGE_COUNT = 50


io = remote(TARGET_HOST, TARGET_PORT)
