# Assignment 1: API Endpoint Discovery

**Difficulty:** Beginner
**Estimated Time:** 1-2 hours
**Points:** 100

## Learning Objectives

By completing this assignment, you will:

- Read and parse large files in Python
- Use regular expressions to extract patterns from text
- Make HTTP GET requests with the `requests` library
- Iterate through results and search for specific content
- Handle HTTP responses and parse text data
- Understand UUID format and structure
- Practice efficient file processing

## Scenario Description

### The Challenge: "The Hidden Endpoint"

You've discovered a minified JavaScript file (`app.min.js`) from a web application. The file contains hundreds of API endpoint URLs, each with a unique UUID identifier in the format:

```text
/api/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

One of these endpoints contains a secret flag, but which one? Manual testing would take hours. Your mission is to automate the discovery process!

**Your Mission:**

1. Read the `app.min.js` file
2. Extract all UUID-based API endpoints using regex
3. Make HTTP requests to each endpoint
4. Find the endpoint that returns the flag

**The Flag Format:** `FLAG{UUID_Discovery_Complete_<random_hex>}`

Where `<random_hex>` is a 16-character hexadecimal string randomly generated when the server starts. Each instance has a unique flag.

### Real-World Context

This simulates real-world scenarios where you need to:

- **Analyze JavaScript files:** Frontend code often contains API endpoints
- **Enumerate endpoints:** Discover all possible API routes
- **Automate testing:** Manual testing of hundreds of endpoints is impractical
- **Parse minified code:** Real applications use minified/obfuscated code
- **Handle large datasets:** Process files with thousands of lines efficiently

Similar techniques are used in:

- **Bug Bounty Hunting:** Finding hidden or undocumented endpoints
- **Security Assessments:** Enumerating all API routes
- **Reverse Engineering:** Understanding web application structure
- **Asset Discovery:** Finding all resources in a web application

## Requirements

### Python Libraries

```txt
requests==2.31.0
```

### System Requirements

- Python 3.10+
- Docker and Docker Compose (for challenge server)

### Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Start the challenge server (generates app.min.js with 1000 endpoints)
docker-compose up -d

# Verify server is running
curl http://localhost:5000/api/health
# Should return: {"status": "healthy"}

# Check that app.min.js was generated
ls -lh app.min.js
# Should show a file of several hundred KB
```

## Your Tasks

### Task 1: Read the File (20 points)

Open and read the `app.min.js` file:

```python
with open('app.min.js', 'r') as file:
    content = file.read()
    # or
    lines = file.readlines()
```

### Task 2: Extract UUID Endpoints with Regex (30 points)

Use regular expressions to find all UUID-based API endpoints:

**UUID Format:** `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

- Each `x` is a hexadecimal digit (0-9, a-f)
- Format: 8-4-4-4-12 characters separated by hyphens

**Endpoint Format:** `/api/{uuid}`

**Example endpoints:**

```text
/api/a1b2c3d4-e5f6-7890-abcd-ef1234567890
/api/12345678-90ab-cdef-1234-567890abcdef
/api/f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**Regex Pattern:**

```python
import re

pattern = re.compile(r'(\/api\/[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12})')
```

Breaking down the pattern:

- `\/api\/` - Literal string "/api/"
- `[a-f\d]{8}` - 8 hex digits
- `-` - Literal hyphen
- `[a-f\d]{4}` - 4 hex digits (repeated 3 times)
- `[a-f\d]{12}` - 12 hex digits

### Task 3: Make HTTP Requests (25 points)

For each discovered endpoint, make a GET request:

```python
import requests

base_url = "http://localhost:5000"

for endpoint in endpoints:
    response = requests.get(f"{base_url}{endpoint}")
    print(f"Tested: {endpoint} - Status: {response.status_code}")
```

### Task 4: Find the Flag (25 points)

Check each response for the flag. The flag-containing response will have "FLAG{" in the text:

```python
if "FLAG{" in response.text:
    print(f"Found flag at: {endpoint}")
    print(response.text)
```

## Starter Code Overview

The `starter.py` file provides:

1. **read_endpoints()** - Read and parse app.min.js
2. **extract_uuid_endpoints()** - Use regex to find endpoints
3. **test_endpoint()** - Make HTTP request to single endpoint
4. **find_flag()** - Search all endpoints for the flag

## Hints

<details>
<summary>Hint 1: Reading Files (Click to reveal)</summary>

Python provides multiple ways to read files:

```python
# Method 1: Read entire file
with open('app.min.js', 'r') as file:
    content = file.read()

# Method 2: Read line by line (more memory efficient)
with open('app.min.js', 'r') as file:
    for line in file:
        # Process each line
        pass

# Method 3: Read all lines into a list
with open('app.min.js', 'r') as file:
    lines = file.readlines()
```

For large files, reading line by line is more efficient.

</details>

<details>
<summary>Hint 2: Regular Expression Basics</summary>

Regular expressions are patterns for matching text:

```python
import re

# Compile pattern for better performance
pattern = re.compile(r'pattern_here')

# Find all matches in text
matches = pattern.findall(text)

# Find all matches with positions
for match in pattern.finditer(text):
    print(match.group())  # The matched text
    print(match.start())  # Starting position
```

For UUID pattern:

- `\d` matches digits (0-9)
- `[a-f]` matches lowercase letters a-f
- `[a-f\d]` matches hex digits (0-9, a-f)
- `{n}` matches exactly n occurrences
- `()` creates a capture group

</details>

<details>
<summary>Hint 3: Making Requests</summary>

The `requests` library makes HTTP requests simple:

```python
import requests

# GET request
response = requests.get('http://example.com/api/endpoint')

# Check status code
if response.status_code == 200:
    print("Success!")

# Get response text
content = response.text

# Parse JSON response
data = response.json()

# Check if string is in response
if "FLAG{" in response.text:
    print("Found it!")
```

</details>

<details>
<summary>Hint 4: Complete Solution Structure</summary>

```python
import re
import requests

# Configuration
url = "http://localhost:5000"
filename = "app.min.js"

# Regex pattern for UUID endpoints
pattern = re.compile(r'(\/api\/[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12})')

# Read file and extract endpoints
with open(filename, 'r') as file:
    for line in file.readlines():
        matches = pattern.findall(line)

        # Test each endpoint found
        for match in matches:
            r = requests.get(f"{url}{match}")

            # Check for flag
            if "FLAG{" in r.text:
                print(f"Found at: {match}")
                print(r.text)
                break
```

</details>

## Test Cases

```bash
# Test 1: Server is running
curl http://localhost:5000/api/health
# Expected: {"status": "healthy"}

# Test 2: File exists and has content
wc -l app.min.js
# Expected: Several hundred lines

# Test 3: Can extract endpoints
python -c "import re; print(len(re.findall(r'\/api\/[a-f\d-]{36}', open('app.min.js').read())))"
# Expected: ~1000 endpoints

# Test 4: Run solution
python solution.py
# Expected: FLAG{UUID_Discovery_Complete_<16_hex_chars>}
```

## Extension Challenges

### Extension 1: Multithreading (30 points)

Speed up endpoint testing with concurrent requests:

```python
from concurrent.futures import ThreadPoolExecutor
import requests

def test_endpoint(endpoint):
    response = requests.get(f"{base_url}{endpoint}")
    if "FLAG{" in response.text:
        return endpoint, response.text
    return None

with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(test_endpoint, endpoints)
    for result in results:
        if result:
            print(f"Found: {result}")
```

### Extension 2: Progress Bar (15 points)

Add a progress indicator for user feedback:

```python
from tqdm import tqdm

for endpoint in tqdm(endpoints, desc="Testing endpoints"):
    # Test endpoint
    pass
```

### Extension 3: Response Caching (20 points)

Cache responses to avoid duplicate requests:

```python
cache = {}

def get_with_cache(url):
    if url not in cache:
        cache[url] = requests.get(url)
    return cache[url]
```

### Extension 4: Pattern Variations (25 points)

Find other endpoint patterns in the file:

- `/v1/api/{uuid}`
- `/admin/{uuid}`
- `/internal/{uuid}`

Create a flexible regex that can find multiple patterns.

## Common Pitfalls

### Issue: "FileNotFoundError: app.min.js"

**Cause:** File hasn't been generated yet
**Solution:**

```bash
# Make sure Docker container is running
docker-compose ps

# If not running, start it
docker-compose up -d

# Wait a few seconds for file generation
sleep 5

# Verify file exists
ls -lh app.min.js
```

### Issue: "Connection refused"

**Cause:** Server not running or wrong port
**Solution:**

```bash
# Check if port 5000 is being used
lsof -i :5000

# Check Docker logs
docker-compose logs

# Restart containers
docker-compose down && docker-compose up -d
```

### Issue: "No matches found"

**Cause:** Incorrect regex pattern
**Solution:** Test your regex pattern first:

```python
import re

pattern = re.compile(r'\/api\/[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}')

# Test with a known UUID
test = "/api/12345678-90ab-cdef-1234-567890abcdef"
print(pattern.findall(test))  # Should print: ['/api/12345678-90ab-cdef-1234-567890abcdef']
```

### Issue: "Too many requests"

**Cause:** Sending requests too quickly
**Solution:** Add delays between requests:

```python
import time

for endpoint in endpoints:
    response = requests.get(f"{url}{endpoint}")
    time.sleep(0.1)  # 100ms delay
```

## Security Lessons Learned

After completing this assignment, you should understand:

1. **Minified code still leaks information** - Frontend code can reveal API structure
2. **UUIDs provide obscurity, not security** - They're guessable if you have examples
3. **All endpoints should have authentication** - Don't rely on "hidden" URLs
4. **Rate limiting is important** - Prevent endpoint enumeration attacks
5. **Automation is powerful** - Manual testing doesn't scale

## Real-World Examples

Similar techniques have been used to discover:

- **Hidden admin panels** - UUID-based admin routes
- **Debug endpoints** - Development endpoints left in production
- **API documentation** - Swagger/OpenAPI endpoints
- **File uploads** - Unrestricted upload endpoints
- **Internal APIs** - Endpoints meant for internal use only

## Resources

- **Python Regex Documentation:** <https://docs.python.org/3/library/re.html>
- **Requests Documentation:** <https://requests.readthedocs.io/>
- **Regex101:** <https://regex101.com/> (test regex patterns)
- **UUID Format:** <https://en.wikipedia.org/wiki/Universally_unique_identifier>
- **Python File I/O:** <https://docs.python.org/3/tutorial/inputoutput.html>

## Grading Rubric

| Criteria | Points |
|----------|--------|
| Task 1: File reading | 20 |
| Task 2: Regex extraction | 30 |
| Task 3: HTTP requests | 25 |
| Task 4: Flag discovery | 25 |
| **Total** | **100** |
| Extension challenges | +90 |
| Code quality | +10 |

## Submission Requirements

Submit:

1. **solution.py** - Your working script
2. **flag.txt** - The flag you discovered
3. **endpoints.txt** - List of all extracted endpoints (optional)

---

**Flag Format:** `FLAG{UUID_Discovery_Complete_<random_hex>}`

**Note:** The flag contains a randomly generated 16-character hexadecimal component that changes each time the server restarts. This prevents flag sharing and ensures each student instance is unique.

Good luck! Remember: in real-world scenarios, always have authorization before testing endpoints.
