#!/usr/bin/env python3
"""
Assignment 3: Automated Math Challenge Solver - Complete Solution
The Math Gauntlet

This solution demonstrates automated problem-solving using pwntools,
regex parsing, and various mathematical solving techniques.
"""

from pwn import context, remote, log
import re
import math
from typing import Optional


# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 9999
CHALLENGE_COUNT = 50


class MathSolver:
    """
    Automated solver for math challenge server.

    Demonstrates:
    - Remote service interaction with pwntools
    - Regex pattern matching for parsing
    - Multi-type equation solving
    - Error handling and recovery
    """

    def __init__(self, host: str, port: int):
        """
        Initialize the solver.

        Args:
            host: Challenge server hostname
            port: Challenge server port
        """
        self.host = host
        self.port = port
        self.conn = None
        self.solved_count = 0

    def connect(self) -> bool:
        """
        Connect to the challenge server using pwntools.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Establish connection
            context.log_level = "warning"  # Reduce pwntools verbosity
            self.conn = remote(self.host, self.port)

            # Receive welcome banner
            banner = self.conn.recvuntil(b"Press ENTER to start...")
            print("[+] Connected to server")
            print(banner.decode())

            # Send ENTER to start challenges
            self.conn.sendline(b"")

            return True

        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def parse_challenge(self, line: str) -> Optional[str]:
        """
        Extract the equation from challenge line.

        Args:
            line: Raw line from server

        Returns:
            Just the equation part, or None if parsing failed
        """
        # Pattern matches: "Challenge X/Y: <equation>"
        match = re.search(r"Challenge \d+/\d+: (.+)", line)

        if match:
            equation = match.group(1).strip()
            return equation

        return None

    def solve_equation(self, equation: str) -> Optional[int]:
        """
        Solve the equation by routing to appropriate solver based on prefix.

        Args:
            equation: The mathematical equation to solve

        Returns:
            Integer answer, or None if solving failed
        """
        try:
            # Check for equation type based on prefix
            if equation.startswith("CALC:"):
                return self.solve_arithmetic(equation)
            elif equation.startswith("POW:"):
                return self.solve_modular(equation)
            elif equation.startswith("ALGEBRA:"):
                return self.solve_algebra(equation)
            elif equation.startswith("BINARY:"):
                return self.solve_binary_op(equation)
            elif (
                equation.startswith("HEX:")
                or equation.startswith("BIN:")
                or equation.startswith("OCT:")
            ):
                return self.solve_conversion(equation)
            elif equation.startswith("FACT:"):
                parts = equation.split(":")[1].strip().split()
                n = int(parts[0])
                return math.factorial(n)
            elif equation.startswith("GCD:"):
                parts = equation.split(":")[1].strip().split()
                a, b = int(parts[0]), int(parts[1])
                return math.gcd(a, b)
            elif equation.startswith("LCM:"):
                parts = equation.split(":")[1].strip().split()
                a, b = int(parts[0]), int(parts[1])
                return abs(a * b) // math.gcd(a, b)
            elif equation.startswith("SQRT:"):
                parts = equation.split(":")[1].strip().split()
                n = int(parts[0])
                return int(math.sqrt(n))

            # Fallback: try arithmetic
            return self.solve_arithmetic(equation)

        except Exception as e:
            log.error(f"Error solving '{equation}': {e}")
            return None

    def solve_arithmetic(self, equation: str) -> Optional[int]:
        """
        Solve basic arithmetic expressions.

        Format: CALC: <expression>

        Args:
            equation: Arithmetic expression

        Returns:
            Result as integer
        """
        # Extract expression after "CALC: "
        expr = equation.split(":", 1)[1].strip()

        # Safe evaluation
        try:
            result = eval(expr)

            # Convert to integer
            if isinstance(result, float):
                result = int(result)

            return result

        except Exception as e:
            log.error(f"Failed to evaluate arithmetic: {expr} ({e})")
            return None

    def solve_algebra(self, equation: str) -> Optional[int]:
        """
        Solve simple linear algebra: ax + b = c or ax - b = c

        Format: ALGEBRA: <coefficient>x + <constant> = <result>

        Args:
            equation: Algebra equation

        Returns:
            Value of x as integer
        """
        # Extract equation after "ALGEBRA: "
        expr = equation.split(":", 1)[1].strip()

        # Pattern: coefficient * x (+ or -) constant = result
        match = re.search(r"(\d+)x\s*([+-])\s*(\d+)\s*=\s*(\d+)", expr)

        if match:
            coefficient = int(match.group(1))
            operation = match.group(2)
            constant = int(match.group(3))
            result = int(match.group(4))

            # Solve for x
            if operation == "+":
                # coefficient * x + constant = result
                # x = (result - constant) / coefficient
                x = (result - constant) / coefficient
            else:  # operation == '-'
                # coefficient * x - constant = result
                # x = (result + constant) / coefficient
                x = (result + constant) / coefficient

            return int(x)

        return None

    def solve_modular(self, equation: str) -> Optional[int]:
        """
        Solve modular exponentiation.

        Format: POW: <base> <exponent> <modulus>

        Args:
            equation: Modular exponentiation expression

        Returns:
            Result of pow(base, exp, mod)
        """
        # Extract numbers after "POW: "
        parts = equation.split(":", 1)[1].strip().split()

        if len(parts) == 3:
            base = int(parts[0])
            exponent = int(parts[1])
            modulus = int(parts[2])

            result = pow(base, exponent, modulus)
            return result

        return None

    def solve_binary_op(self, equation: str) -> Optional[int]:
        """
        Solve binary operations: XOR, AND, OR

        Format: BINARY: <binary1> <operation> <binary2>

        Args:
            equation: Binary operation

        Returns:
            Result as integer
        """
        # Extract parts after "BINARY: "
        expr = equation.split(":", 1)[1].strip()
        parts = expr.split()

        if len(parts) == 3:
            num1 = int(parts[0], 2)  # Convert binary string to int
            operation = parts[1]
            num2 = int(parts[2], 2)

            # Apply operation
            if operation == "XOR":
                return num1 ^ num2
            elif operation == "AND":
                return num1 & num2
            elif operation == "OR":
                return num1 | num2

        return None

    def solve_conversion(self, equation: str) -> Optional[int]:
        """
        Solve base conversions.

        Formats:
        - HEX: <value>
        - BIN: <value>
        - OCT: <value>

        Args:
            equation: Base conversion request

        Returns:
            Decimal integer
        """
        # Extract type and value
        parts = equation.split(":", 1)
        if len(parts) != 2:
            return None

        conv_type = parts[0].strip()
        value = parts[1].strip()

        # Convert based on type
        if conv_type == "HEX":
            return int(value, 16)
        elif conv_type == "BIN":
            return int(value, 2)
        elif conv_type == "OCT":
            return int(value, 8)

        return None

    def run_challenge(self):
        """Main loop to solve all challenges."""
        print("=" * 60)
        print("Math Challenge Solver - Complete Solution")
        print("=" * 60)

        # Connect to server
        print(f"\n[*] Connecting to {self.host}:{self.port}...")
        if not self.connect():
            log.error("Failed to establish connection")
            return

        import time

        start_time = time.time()

        try:
            # Solve all challenges
            for i in range(1, CHALLENGE_COUNT + 1):
                # Receive challenge
                try:
                    # Read until "Answer: " prompt
                    challenge_data = self.conn.recvuntil(b"Answer: ", timeout=5)
                    challenge_line = challenge_data.decode()

                    # Parse the equation
                    equation = self.parse_challenge(challenge_line)

                    if not equation:
                        log.error(f"Failed to parse challenge {i}")
                        print(f"[DEBUG] Received: {challenge_line}")
                        return

                    # Solve the equation
                    answer = self.solve_equation(equation)

                    if answer is None:
                        log.error(f"Failed to solve: {equation}")
                        return

                    # Display progress every 10 challenges
                    if i % 10 == 0 or i == 1:
                        print(
                            f"[*] Challenge {i}/{CHALLENGE_COUNT}: {equation[:50]}... = {answer}"
                        )

                    # Send answer
                    self.conn.sendline(str(answer).encode())
                    self.solved_count = i

                except EOFError:
                    log.error("Connection closed unexpectedly")
                    return

            # Receive final message with flag
            final_msg = self.conn.recvall(timeout=2)
            elapsed = time.time() - start_time

            print("\n" + "=" * 60)
            print(final_msg.decode())
            print("=" * 60)
            print(f"\n[+] Completed in {elapsed:.2f} seconds")
            print(f"[+] Solved: {self.solved_count}/{CHALLENGE_COUNT}")

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except Exception as e:
            log.error(f"Error during challenge: {e}")
        finally:
            if self.conn:
                self.conn.close()


def main():
    """Main entry point."""
    solver = MathSolver(TARGET_HOST, TARGET_PORT)
    solver.run_challenge()


if __name__ == "__main__":
    main()
