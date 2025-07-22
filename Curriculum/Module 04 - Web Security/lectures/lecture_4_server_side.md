# Server Side Vulnerabilities

## SQL injection (SQLi)

![SQLi Cover](images/sqli_cover.png)

SQL injection (SQLi) is a critical web security vulnerability that enables attackers to manipulate the database queries made by an application. This allows them to access unauthorized data, potentially compromising user privacy and application integrity. Attackers can also modify or delete data, leading to persistent changes in the application. In severe cases, SQLi can be used to compromise the server or launch denial-of-service attacks.

### Impact of SQL Injections

1. **Data Manipulation**: Attackers can tamper with existing data, potentially altering, deleting, or inserting new records.

1. **Identity Spoofing**: Attackers can gain unauthorized access by pretending to be someone else, potentially leading to unauthorized transactions and actions.

1. **Data Disclosure**: Entire databases can be exposed, leading to theft of sensitive information like user details, financial records, personal messages, etc.

1. **Data Destruction**: Databases can be destroyed or rendered unavailable, disrupting business operations and causing financial losses.

1. **Admin Rights**: Attackers can potentially gain administrative rights to the database server, giving them unrestricted access and control.

### SQL Injection (SQLi) Example for Web Login

#### **Context:**

Imagine a website where users log in with their username and password. The website queries a database to verify these credentials.

#### **Normal Query:**

The application might use SQL like:

```sql
SELECT * FROM users WHERE username='INPUT_USERNAME' AND password='INPUT_PASSWORD';
```

Where `INPUT_USERNAME` and `INPUT_PASSWORD` are replaced by what the user enters.

#### **SQLi Attack:**

An attacker enters:

```vbnet
Username: admin' --
Password: [anything]
```

Resulting in the SQL:

```sql
SELECT * FROM users WHERE username='admin' --' AND password='[anything]';
```

The `--` is a comment out symbol in SQL. The rest of the query is ignored, authenticating as 'admin' without needing the password!

#### **Consequences:**

1. Unauthorized Access: Attacker logs in as an admin without knowing the password.
1. Potential Data Breach: The attacker can exploit further vulnerabilities.

#### **Explanation:**

The application directly uses user input in SQL, allowing query manipulation.

#### **Prevention:**

- Use parameterized queries or prepared statements.
- Avoid directly adding user input into SQL queries.
- Utilize web application firewalls and security audits.

> **For more Examples see:** <https://portswigger.net/web-security/sql-injection#sql-injection-examples>

## Server-side request forgery (SSRF)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.

### Impact of SSRF (Server-Side Request Forgery) Attacks

1. **Unauthorized Access**: SSRF attacks can bypass access controls, potentially leading to unauthorized actions or data access within internal systems.

1. **Data Exfiltration**: Sensitive data from the server or connected backend systems can be accessed, which may include personal, credential, or confidential information.

1. **Internal Probing**: SSRF can be utilized to map internal networks, discover services on other machines, and identify further vulnerabilities within an internal network.

1. **Arbitrary Command Execution**: Some SSRF vulnerabilities may lead to remote code execution, allowing attackers to run arbitrary commands on the server or related systems.

1. **Secondary Attacks**: The server can be manipulated to make requests to external systems, leading to secondary attacks that appear to come from the organization itself.

1. **Denial of Service**: SSRF attacks can result in service overload, potentially leading to denial of service for internal services.

1. **Cross-site Scripting (XSS)**: If SSRF responses are reflected back to the client, it could be exploited for XSS attacks.

#### Mitigation Strategies

- Validate and sanitize all user inputs.
- Minimize exposure of internal services.
- Implement network segmentation and firewall rules to restrict internal network access.

## Resources

- <https://portswigger.net/web-security/sql-injection>
- <https://owasp.org/www-community/attacks/SQL_Injection>
- <https://book.hacktricks.xyz/pentesting-web/sql-injection>
- <https://portswigger.net/web-security/ssrf>
