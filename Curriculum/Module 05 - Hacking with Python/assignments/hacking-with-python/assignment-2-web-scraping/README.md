# Assignment 4: Web Scraping & Credential Harvesting

**Difficulty:** Advanced
**Estimated Time:** 4-5 hours
**Points:** 200

## Learning Objectives

- Master `requests`, `BeautifulSoup4`, and `selenium` for web scraping
- Handle dynamic JavaScript-rendered content
- Automate multi-page authentication flows
- Extract data from complex HTML/DOM structures
- Handle cookies, sessions, and CSRF tokens
- Bypass basic anti-scraping measures
- Work with form automation and submission

## Scenario: "The Hidden Portal"

You've discovered a company intranet at `http://localhost:8080` that requires multi-step authentication. Your goal is to automate the entire process to extract a hidden employee database.

**Challenge Flow:**

1. **Phase 1:** Navigate to login page and extract CSRF token
2. **Phase 2:** Submit credentials and handle session cookies
3. **Phase 3:** Solve a JavaScript-rendered CAPTCHA challenge
4. **Phase 4:** Navigate through paginated employee directory
5. **Phase 5:** Extract and parse employee data from dynamic tables
6. **Phase 6:** Find the flag hidden in a specific employee's profile

## Requirements

```txt
requests==2.31.0
beautifulsoup4==4.12.2
selenium==4.15.2
lxml==4.9.3
webdriver-manager==4.0.1
```

## Tasks

### Task 1: Static Page Scraping (30 points)

Use `requests` and `BeautifulSoup` to:

- GET the login page
- Parse HTML to extract CSRF token from hidden form field
- Extract form action URL

```python
from bs4 import BeautifulSoup
import requests

response = requests.get('http://localhost:8080/login')
soup = BeautifulSoup(response.content, 'html.parser')
csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
```

### Task 2: Form Submission with Session Handling (40 points)

- Create session to persist cookies
- Submit login form with CSRF token
- Handle redirect responses
- Verify successful authentication

```python
session = requests.Session()
data = {
    'username': 'admin',
    'password': 'secret',
    'csrf_token': csrf_token
}
response = session.post('http://localhost:8080/login', data=data)
```

### Task 3: Dynamic Content with Selenium (50 points)

Use Selenium for JavaScript-rendered content:

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

driver = webdriver.Chrome()
driver.get('http://localhost:8080/dashboard')

# Wait for dynamic content to load
element = WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.ID, "employee-table"))
)
```

### Task 4: Pagination Handling (40 points)

Navigate through multi-page results:

- Detect "Next" button/link
- Extract data from each page
- Combine results from all pages

### Task 5: Data Extraction & Flag Retrieval (40 points)

- Parse employee table
- Extract structured data (name, email, department, etc.)
- Find employee with specific criteria containing flag

## Extension Challenges

### Extension 1: Anti-Scraping Bypass (50 points)

- Handle rate limiting with delays
- Rotate User-Agent headers
- Solve simple CAPTCHA challenges

### Extension 2: Headless Browser Mode (20 points)

Run Selenium in headless mode for faster scraping:

```python
options = webdriver.ChromeOptions()
options.add_argument('--headless')
driver = webdriver.Chrome(options=options)
```

### Extension 3: Data Export (30 points)

Export scraped data to:

- CSV file
- JSON file
- SQLite database

## Sample Code Structure

```python
class WebScraper:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.driver = None

    def get_csrf_token(self):
        """Extract CSRF token from login page."""
        pass

    def login(self, username, password):
        """Authenticate and establish session."""
        pass

    def init_selenium(self):
        """Initialize Selenium WebDriver."""
        pass

    def scrape_employee_page(self, page_num):
        """Scrape single page of employee data."""
        pass

    def get_all_employees(self):
        """Scrape all pages and combine results."""
        pass

    def find_flag(self, employees):
        """Search employee data for flag."""
        pass
```

## Grading Rubric

| Criteria | Points |
|----------|--------|
| Task 1: Static scraping | 30 |
| Task 2: Session handling | 40 |
| Task 3: Dynamic content | 50 |
| Task 4: Pagination | 40 |
| Task 5: Flag extraction | 40 |
| **Total** | **200** |
| Extensions | +100 |

## Resources

- **BeautifulSoup Docs:** <https://www.crummy.com/software/BeautifulSoup/bs4/doc/>
- **Selenium Docs:** <https://selenium-python.readthedocs.io/>
- **Requests Docs:** <https://requests.readthedocs.io/>

---

**Flag Format:** `FLAG{Web_Scraping_Masters_The_DOM}`
