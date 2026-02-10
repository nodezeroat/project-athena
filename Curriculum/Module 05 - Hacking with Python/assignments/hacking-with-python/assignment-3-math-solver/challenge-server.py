#!/usr/bin/env python3
"""
Math Challenge Server

This server generates 50 random mathematical equations that must be
solved within 30 seconds. It's designed to require automation - no
human could solve them all fast enough.

Usage:
    python challenge-server.py

The server listens on port 9999 and accepts connections via netcat or pwntools.
"""

import socket
import random
import time
import threading
import secrets


# Server configuration
HOST = "0.0.0.0"
PORT = 9999
CHALLENGE_COUNT = 50
TIME_LIMIT = 30  # seconds

# Generate random flag component on startup

random_component = secrets.token_hex(8)  # 16 character hex string
FLAG = f"FLAG{{Automation_Beats_Manual_{random_component}}}"


class MathChallenge:
    """Generate various types of mathematical challenges."""

    @staticmethod
    def basic_arithmetic():
        """Generate basic arithmetic problem."""
        operations = [
            lambda: f"{random.randint(100, 999)} + {random.randint(100, 999)}",
            lambda: f"{random.randint(100, 999)} - {random.randint(10, 500)}",
            lambda: f"{random.randint(10, 999)} * {random.randint(10, 999)}",
            lambda: f"{random.randint(1000, 9999)} / {random.choice([2, 4, 5, 10, 20])}",
            lambda: f"{random.randint(10, 100)} ** {random.randint(2, 4)}",
        ]

        expr = random.choice(operations)()
        answer = eval(expr)

        # For division, return integer result
        if "/" in expr:
            answer = int(answer)

        return f"CALC: {expr}", answer

    @staticmethod
    def modular_arithmetic():
        """Generate modular exponentiation problem."""
        base = random.randint(100, 999)
        exponent = random.randint(100, 999)
        modulus = random.randint(100, 999)

        question = f"POW: {base} {exponent} {modulus}"
        answer = pow(base, exponent, modulus)

        return question, answer

    @staticmethod
    def algebra():
        """Generate simple linear algebra problem: ax + b = c"""
        coefficient = random.randint(2, 10)
        constant = random.randint(1, 50)
        x_value = random.randint(1, 20)

        # Calculate result based on random operation
        if random.choice([True, False]):
            # Addition: coefficient*x + constant = result
            result = coefficient * x_value + constant
            question = f"ALGEBRA: {coefficient}x + {constant} = {result}"
        else:
            # Subtraction: coefficient*x - constant = result
            result = coefficient * x_value - constant
            question = f"ALGEBRA: {coefficient}x - {constant} = {result}"

        answer = x_value

        return question, answer

    @staticmethod
    def binary_operations():
        """Generate binary operation problems."""
        operations = {
            "XOR": lambda a, b: a ^ b,
            "AND": lambda a, b: a & b,
            "OR": lambda a, b: a | b,
        }

        op_name = random.choice(list(operations.keys()))
        op_func = operations[op_name]

        num1 = random.randint(1, 255)
        num2 = random.randint(1, 255)

        question = f"BINARY: {bin(num1)[2:]} {op_name} {bin(num2)[2:]}"
        answer = op_func(num1, num2)

        return question, answer

    @staticmethod
    def base_conversion():
        """Generate base conversion problems."""
        conversion_type = random.choice(["hex", "binary", "octal"])

        if conversion_type == "hex":
            num = random.randint(1000, 65535)
            question = f"HEX: {hex(num)[2:].upper()}"
        elif conversion_type == "binary":
            num = random.randint(100, 1023)
            question = f"BIN: {bin(num)[2:]}"
        else:  # octal
            num = random.randint(100, 1023)
            question = f"OCT: {oct(num)[2:]}"

        return question, num

    @staticmethod
    def advanced_math():
        """Generate advanced math problems."""
        import math

        problem_type = random.choice(["factorial", "gcd", "lcm", "sqrt"])

        if problem_type == "factorial":
            n = random.randint(5, 12)
            question = f"FACT: {n}"
            answer = math.factorial(n)
        elif problem_type == "gcd":
            a = random.randint(100, 9999)
            b = random.randint(100, 9999)
            question = f"GCD: {a} {b}"
            answer = math.gcd(a, b)
        elif problem_type == "lcm":
            a = random.randint(10, 100)
            b = random.randint(10, 100)
            question = f"LCM: {a} {b}"
            answer = abs(a * b) // math.gcd(a, b)
        else:  # sqrt
            n = random.choice(
                [4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225]
            )
            question = f"SQRT: {n}"
            answer = int(math.sqrt(n))

        return question, answer

    @staticmethod
    def generate_random_challenge():
        """Generate a random challenge of any type."""
        challenge_types = [
            MathChallenge.basic_arithmetic,
            MathChallenge.basic_arithmetic,  # More frequent
            MathChallenge.basic_arithmetic,
            MathChallenge.modular_arithmetic,
            MathChallenge.algebra,
            MathChallenge.algebra,  # More frequent
            MathChallenge.binary_operations,
            MathChallenge.base_conversion,
            MathChallenge.advanced_math,
        ]

        challenge_func = random.choice(challenge_types)
        return challenge_func()


def handle_client(client_socket, client_address):
    """
    Handle a single client connection.

    Args:
        client_socket: The connected client socket
        client_address: Tuple of (host, port)
    """
    try:
        print(f"[+] New connection from {client_address}")

        # Send welcome banner
        banner = b"""
================================================================================
                        MATH CHALLENGE SERVER
================================================================================
Welcome to the Math Gauntlet!

Solve 50 mathematical equations in under 30 seconds to get the flag.
No human could solve them all that fast - you'll need to write a script!

Equation types include:
  - Basic arithmetic
  - Modular exponentiation
  - Linear algebra
  - Binary operations (XOR, AND, OR)
  - Base conversions (hex, binary, octal)
  - Advanced math (factorial, gcd, lcm, sqrt)

Good luck!
================================================================================

Press ENTER to start...
"""
        client_socket.send(banner)

        # Wait for client to be ready
        client_socket.recv(1024)

        # Start timer
        start_time = time.time()

        # Generate and send challenges
        for i in range(1, CHALLENGE_COUNT + 1):
            # Check time limit
            elapsed = time.time() - start_time
            if elapsed > TIME_LIMIT:
                msg = f"\n\n[!] TIME LIMIT EXCEEDED ({elapsed:.2f}s > {TIME_LIMIT}s)\n"
                msg += "You need to automate this challenge!\n"
                client_socket.send(msg.encode())
                return

            # Generate challenge
            question, correct_answer = MathChallenge.generate_random_challenge()

            # Send challenge
            prompt = f"\nChallenge {i}/{CHALLENGE_COUNT}: {question}\n"
            prompt += "Answer: "
            client_socket.send(prompt.encode())

            # Receive answer
            try:
                client_socket.settimeout(5.0)  # 5 second timeout per question
                answer_data = client_socket.recv(1024).strip()

                if not answer_data:
                    client_socket.send(b"\n[-] Connection lost\n")
                    return

                # Parse answer
                try:
                    user_answer = int(answer_data.decode().strip())
                except ValueError:
                    # Try parsing as float then convert to int
                    try:
                        user_answer = int(float(answer_data.decode().strip()))
                    except (ValueError, UnicodeDecodeError):
                        client_socket.send(b"\n[-] Invalid answer format\n")
                        return

                # Check answer
                if user_answer != correct_answer:
                    msg = (
                        f"\n\n[-] WRONG! Expected {correct_answer}, got {user_answer}\n"
                    )
                    msg += f"[*] You solved {i-1}/{CHALLENGE_COUNT} challenges\n"
                    client_socket.send(msg.encode())
                    return

                # Correct answer
                if i % 10 == 0:
                    msg = f"[+] Correct! ({i}/{CHALLENGE_COUNT} complete)\n"
                    client_socket.send(msg.encode())

            except socket.timeout:
                client_socket.send(b"\n\n[-] TIMEOUT! Too slow.\n")
                return

        # All challenges solved!
        elapsed = time.time() - start_time

        success_msg = f"""

================================================================================
                           CONGRATULATIONS!
================================================================================

You solved all {CHALLENGE_COUNT} challenges in {elapsed:.2f} seconds!

Here is your flag:

    {FLAG}

Well done! You've demonstrated the power of automation.
================================================================================

"""
        client_socket.send(success_msg.encode())

        print(f"[+] {client_address} completed the challenge in {elapsed:.2f}s")

    except Exception as e:
        print(f"[-] Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection closed: {client_address}")


def run_server():
    """Run the challenge server."""
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)

        print("=" * 60)
        print("Math Challenge Server")
        print("=" * 60)
        print(f"[*] Listening on {HOST}:{PORT}")
        print(f"[*] Challenges: {CHALLENGE_COUNT}")
        print(f"[*] Time limit: {TIME_LIMIT} seconds")
        print(f"[*] Flag: {FLAG}")
        print("=" * 60)
        print("\nTest connection with: nc localhost 9999")
        print("or: python solution.py\n")

        while True:
            try:
                client_socket, client_address = server_socket.accept()

                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=handle_client, args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()

            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
                break
            except Exception as e:
                print(f"[-] Error accepting connection: {e}")

    except Exception as e:
        print(f"[-] Server error: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    run_server()
