# Assignment 2: Secure Code Review and Remediation

## Objective

The purpose of this assignment is to develop your skills in identifying security vulnerabilities in source code and implementing effective remediation strategies. You will analyze vulnerable code snippets, identify security flaws, explain the vulnerabilities, and provide secure implementations. This assignment emphasizes both offensive (identifying vulnerabilities) and defensive (fixing them) security skills.

## Instructions

### Part 1: Vulnerability Identification and Explanation

For each code snippet provided below, you must:

1. **Identify all security vulnerabilities** present in the code
2. **Classify each vulnerability** (e.g., SQL Injection, XSS, CSRF, etc.)
3. **Explain the vulnerability**:
   - How it can be exploited
   - What data or functionality is at risk
   - Potential impact on the application and users
4. **Provide a proof-of-concept attack** (example malicious input or attack vector)

### Part 2: Secure Implementation

For each vulnerable code snippet:

1. **Rewrite the code** to eliminate all identified vulnerabilities
2. **Explain your remediation approach**:
   - What security measures you implemented
   - Why your solution prevents the vulnerability
   - Any trade-offs or considerations
3. **Document security best practices** applied in your solution

---

## Code Snippets to Analyze

### Snippet 1: User Authentication (Python/Flask)

```python
from flask import Flask, request, session, redirect
import sqlite3

app = Flask(__name__)
app.secret_key = 'dev'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        return redirect('/dashboard')
    else:
        return 'Invalid credentials', 401
```

### Snippet 2: User Profile Update (Node.js/Express)

```javascript
const express = require('express');
const app = express();

app.post('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const userData = req.body;

    // Check if user is authenticated
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Update user in database
    User.findByIdAndUpdate(userId, userData, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'User updated', user: user });
    });
});
```

### Snippet 3: File Upload Handler (PHP)

```php
<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    die('Not authenticated');
}

if (isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    $filename = $file['name'];
    $target = 'uploads/' . $filename;

    if ($file['size'] > 5000000) {
        die('File too large');
    }

    if (move_uploaded_file($file['tmp_name'], $target)) {
        $user_id = $_SESSION['user_id'];
        $query = "UPDATE users SET avatar='$target' WHERE id=$user_id";
        mysqli_query($conn, $query);

        echo "File uploaded successfully: <a href='$target'>View</a>";
    } else {
        echo 'Upload failed';
    }
}
?>
```

### Snippet 4: Search Functionality (Python/Django)

```python
from django.shortcuts import render
from django.http import HttpResponse
from .models import Product

def search(request):
    query = request.GET.get('q', '')

    if query:
        # Search products
        products = Product.objects.raw(
            f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
        )

        # Generate HTML response
        html = f"<h1>Search Results for: {query}</h1>"
        html += "<div class='results'>"

        for product in products:
            html += f"<div class='product'>"
            html += f"<h2>{product.name}</h2>"
            html += f"<p>{product.description}</p>"
            html += f"</div>"

        html += "</div>"

        return HttpResponse(html)

    return render(request, 'search.html')
```

### Snippet 5: API Endpoint (Node.js/Express)

```javascript
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'mysecret';

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // Validate credentials (simplified)
    if (username === 'admin' && password === 'admin123') {
        const token = jwt.sign({ username, role: 'admin' }, SECRET_KEY);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/api/admin/users', (req, res) => {
    const token = req.headers.authorization;

    if (token) {
        try {
            const decoded = jwt.decode(token);

            if (decoded.role === 'admin') {
                // Return all users
                User.find({}, (err, users) => {
                    res.json(users);
                });
            } else {
                res.status(403).json({ error: 'Forbidden' });
            }
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    } else {
        res.status(401).json({ error: 'No token provided' });
    }
});
```

### Snippet 6: Password Reset (Python/Flask)

```python
from flask import Flask, request, render_template_string
import smtplib

app = Flask(__name__)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if email exists
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            reset_token = user.id  # SIMPLIFIED
            reset_link = f"https://example.com/reset/{reset_token}"

            # Send email
            message = f"Click here to reset your password: {reset_link}"
            send_email(email, "Password Reset", message)

            return f"Password reset link sent to {email}"
        else:
            return "Email not found"

    # GET request - show form
    template = """
    <html>
    <body>
        <h1>Password Reset</h1>
        <form method="POST">
            <input type="email" name="email" placeholder="Enter your email">
            <button type="submit">Reset Password</button>
        </form>
        <p>User searched for: %s</p>
    </body>
    </html>
    """ % request.args.get('search', '')

    return render_template_string(template)
```

### Snippet 7: Comment System (PHP)

```php
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $comment = $_POST['comment'];
    $post_id = $_POST['post_id'];
    $user_id = $_SESSION['user_id'];

    // Save comment
    $query = "INSERT INTO comments (post_id, user_id, comment, created_at)
              VALUES ($post_id, $user_id, '$comment', NOW())";
    mysqli_query($conn, $query);

    header("Location: post.php?id=$post_id");
    exit;
}

// Display comments
$post_id = $_GET['id'];
$query = "SELECT c.comment, u.username, c.created_at
          FROM comments c
          JOIN users u ON c.user_id = u.id
          WHERE c.post_id = $post_id";

$result = mysqli_query($conn, $query);

echo "<h2>Comments</h2>";
while ($row = mysqli_fetch_assoc($result)) {
    echo "<div class='comment'>";
    echo "<strong>" . $row['username'] . "</strong> ";
    echo "<span>" . $row['created_at'] . "</span>";
    echo "<p>" . $row['comment'] . "</p>";
    echo "</div>";
}
?>

<form method="POST">
    <input type="hidden" name="post_id" value="<?php echo $_GET['id']; ?>">
    <textarea name="comment" required></textarea>
    <button type="submit">Post Comment</button>
</form>
```

### Snippet 8: GraphQL API (Node.js)

```javascript
const { ApolloServer, gql } = require('apollo-server');

const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    password: String!
    ssn: String
    creditCard: String
    isAdmin: Boolean!
  }

  type Query {
    user(id: ID!): User
    users: [User]
  }

  type Mutation {
    updateUser(id: ID!, username: String, email: String, isAdmin: Boolean): User
  }
`;

const resolvers = {
  Query: {
    user: (parent, { id }, context) => {
      return User.findById(id);
    },
    users: () => {
      return User.find({});
    }
  },
  Mutation: {
    updateUser: (parent, args, context) => {
      const { id, ...updates } = args;
      return User.findByIdAndUpdate(id, updates, { new: true });
    }
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
  playground: true
});

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
```

---

## Submission Requirements

### Format

Your submission must include:

1. **Cover Page**:
   - Your name
   - Date
   - Assignment title: "Module 04 - Assignment 2: Secure Code Review and Remediation"

2. **Analysis Section** (for each snippet):
   - Original vulnerable code (properly formatted)
   - List of vulnerabilities identified
   - Detailed explanation of each vulnerability
   - Proof-of-concept attack examples
   - Risk assessment (impact and likelihood)

3. **Remediation Section** (for each snippet):
   - Secure rewritten code (properly formatted)
   - Explanation of fixes applied
   - Security best practices implemented
   - Testing recommendations

4. **Summary Section**:
   - Key lessons learned
   - Common vulnerability patterns observed
   - Best practices for secure coding

### Technical Requirements

- **Document Format**: PDF
- **Code Formatting**: Use proper syntax highlighting and formatting
- **Length**: No strict limit, but be concise and thorough
- **Code Comments**: Include inline comments explaining security measures
- **Testing Evidence**: Optional but recommended - include screenshots of testing your secure code

### Submission

Submit your document as a PDF on Google Drive according to the course naming convention.

---

## Evaluation Criteria

### Vulnerability Identification (40 points)

- **Completeness** (15 points): All vulnerabilities identified in each snippet
- **Accuracy** (15 points): Correct classification and understanding of vulnerabilities
- **Explanation Quality** (10 points): Clear, detailed explanations with examples

### Secure Implementation (40 points)

- **Security** (20 points): Code effectively eliminates all vulnerabilities
- **Code Quality** (10 points): Clean, maintainable, well-commented code
- **Best Practices** (10 points): Application of security best practices and principles

### Documentation (15 points)

- **Clarity** (5 points): Clear, well-organized document
- **Completeness** (5 points): All required sections included
- **Professionalism** (5 points): Proper formatting, grammar, and presentation

### Bonus Points (5 points)

- **Extra Security Measures** (up to 3 points): Additional security enhancements beyond basic fixes
- **Testing Evidence** (up to 2 points): Include evidence of testing your secure implementations

### Total: 100 points (+ 5 bonus)

---

## Expected Vulnerabilities (Hint)

Here are the **categories** of vulnerabilities you should look for (specific instances are for you to find):

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
- Mass Assignment
- Path Traversal
- File Upload Vulnerabilities
- Broken Authentication
- Insufficient Authorization
- Information Disclosure
- Insecure Cryptography
- Server-Side Template Injection (SSTI)
- JWT Security Issues
- GraphQL Authorization Issues

**Note**: Some snippets contain multiple vulnerabilities!

---

## Tips for Success

1. **Read Carefully**: Some snippets have subtle vulnerabilities that are easy to miss
2. **Think Like an Attacker**: For each input, ask "what malicious data could I provide?"
3. **Defense in Depth**: Apply multiple layers of security, not just one fix
4. **Test Your Code**: If possible, set up the code and test your fixes
5. **Refer to Lectures**: Review lecture materials for security best practices
6. **Use OWASP Resources**: OWASP Cheat Sheets are excellent references
7. **Document Everything**: Explain your reasoning clearly

---

## Resources

- **OWASP Cheat Sheet Series**: <https://cheatsheetseries.owasp.org/>
- **OWASP Top 10**: <https://owasp.org/www-project-top-ten/>
- **OWASP API Security Top 10**: <https://owasp.org/www-project-api-security/>
- **PortSwigger Web Security Academy**: <https://portswigger.net/web-security>
- **CWE (Common Weakness Enumeration)**: <https://cwe.mitre.org/>

---

## Academic Integrity

- You may consult course materials, OWASP resources, and official documentation
- You may discuss general concepts with classmates
- **You must write your own code and explanations**
- **Do not share or copy code solutions**
- Cite any external resources used

Plagiarism will result in a zero for the assignment and may lead to further academic consequences.

---

## Deadline

Refer to the course schedule for the specific deadline. Late submissions will be penalized according to the course policy.

---

## Questions?

If you have questions about the assignment:

1. Review the lecture materials first
2. Check the OWASP resources
3. Ask during office hours or lab sessions
4. Post general questions (not solutions) on the course forum

Good luck, and happy secure coding!
