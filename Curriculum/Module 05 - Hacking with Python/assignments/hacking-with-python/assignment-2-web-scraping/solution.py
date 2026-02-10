#!/usr/bin/env python3
"""
Assignment 4: Web Scraping & Credential Harvesting - Solution

Demonstrates web scraping with requests, BeautifulSoup, and Selenium.
"""

import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import time


class WebScraper:
    """Complete scraper implementation."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

    def get_csrf_token(self) -> Optional[str]:
        """Extract CSRF token from login page."""
        try:
            response = self.session.get(f"{self.base_url}/login")
            soup = BeautifulSoup(response.content, "html.parser")

            csrf_input = soup.find("input", {"name": "csrf_token"})
            if csrf_input:
                token = csrf_input.get("value")
                print(f"[+] CSRF token: {token}")
                return token

            return None
        except Exception as e:
            print(f"[-] Error getting CSRF token: {e}")
            return None

    def login(self, username: str, password: str) -> bool:
        """Authenticate and establish session."""
        try:
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                return False

            data = {
                "username": username,
                "password": password,
                "csrf_token": csrf_token,
            }

            response = self.session.post(
                f"{self.base_url}/login", data=data, allow_redirects=True
            )

            if response.status_code == 200 and "dashboard" in response.url:
                print(f"[+] Login successful as {username}")
                return True

            print("[-] Login failed")
            return False

        except Exception as e:
            print(f"[-] Login error: {e}")
            return False

    def scrape_employee_page(self, page_num: int) -> List[Dict]:
        """Scrape single page of employee data."""
        try:
            response = self.session.get(f"{self.base_url}/employees?page={page_num}")
            soup = BeautifulSoup(response.content, "html.parser")

            employees = []
            table = soup.find("table", {"id": "employee-table"})

            if not table:
                return employees

            rows = table.find_all("tr")[1:]  # Skip header row

            for row in rows:
                cols = row.find_all("td")
                if len(cols) >= 4:
                    employee = {
                        "id": cols[0].text.strip(),
                        "name": cols[1].text.strip(),
                        "email": cols[2].text.strip(),
                        "department": cols[3].text.strip(),
                    }
                    employees.append(employee)

            print(f"[+] Scraped {len(employees)} employees from page {page_num}")
            return employees

        except Exception as e:
            print(f"[-] Error scraping page {page_num}: {e}")
            return []

    def get_all_employees(self) -> List[Dict]:
        """Scrape all pages and combine results."""
        all_employees = []
        page = 1

        while True:
            employees = self.scrape_employee_page(page)

            if not employees:
                break

            all_employees.extend(employees)
            page += 1
            time.sleep(0.5)  # Rate limiting

        print(f"[+] Total employees scraped: {len(all_employees)}")
        return all_employees

    def find_flag(self, employees: List[Dict]) -> Optional[str]:
        """Search employee data for flag."""
        for emp in employees:
            # Check if any field contains FLAG
            for key, value in emp.items():
                if "FLAG{" in str(value):
                    print(f"[+] Found flag in employee: {emp['name']}")
                    return value

        # Flag might be in specific employee profile
        for emp in employees:
            if "admin" in emp["name"].lower() or "root" in emp["name"].lower():
                # Fetch detailed profile
                try:
                    response = self.session.get(f"{self.base_url}/employee/{emp['id']}")
                    if "FLAG{" in response.text:
                        import re

                        match = re.search(r"FLAG\{[^}]+\}", response.text)
                        if match:
                            return match.group(0)
                except Exception:
                    pass

        return None

    def run(self):
        """Execute full scraping workflow."""
        print("=" * 60)
        print("Web Scraping Challenge - Solution")
        print("=" * 60)

        # Step 1: Login
        print("\n[*] Step 1: Authenticating...")
        if not self.login("admin", "password123"):
            print("[-] Authentication failed")
            return

        # Step 2: Scrape all employees
        print("\n[*] Step 2: Scraping employee directory...")
        employees = self.get_all_employees()

        if not employees:
            print("[-] No employees found")
            return

        # Step 3: Find flag
        print("\n[*] Step 3: Searching for flag...")
        flag = self.find_flag(employees)

        if flag:
            print("\n" + "=" * 60)
            print(f"🚩 FLAG: {flag}")
            print("=" * 60)
        else:
            print("[-] Flag not found")


def main():
    scraper = WebScraper("http://localhost:8080")
    scraper.run()


if __name__ == "__main__":
    main()
