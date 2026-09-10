# My App Backend

A minimal Node.js + Express backend with user signup, login, logout, and sessions.
Passwords are hashed with bcrypt and users are stored in SQLite.

## Setup

1. Install [Node.js](https://nodejs.org) (LTS) and [Git](https://git-scm.com) if you don't have them.
2. Put your existing HTML file inside a `public/` folder, named `index.html`.
   Your folder should look like:

   ```
   my-app/
   ├── server.js
   ├── package.json
   ├── .gitignore
   ├── README.md
   └── public/
       └── index.html   <- your existing HTML
   ```

3. Install dependencies:

   ```bash
   npm install
   ```

4. Start the server:

   ```bash
   npm start
   ```

5. Open http://localhost:3000 in your browser.

## API endpoints

| Method | Path         | Purpose                          |
|--------|--------------|----------------------------------|
| POST   | /api/signup  | Create an account and log in     |
| POST   | /api/login   | Log in an existing user          |
| POST   | /api/logout  | Log out                          |
| GET    | /api/me      | Get the currently logged-in user |

## Wiring up your HTML

Add JavaScript like this to your page to talk to the backend:

```js
// Sign up
async function signup(email, password) {
  const res = await fetch('/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error);
  return data;
}

// Log in
async function login(email, password) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error);
  return data;
}

// Check who is logged in
async function me() {
  const res = await fetch('/api/me');
  return res.ok ? res.json() : null;
}
```

## Before going to production

- Set a real `SESSION_SECRET` environment variable (do not commit it).
- Serve over HTTPS and set the session cookie to `secure: true`.
- This starter is a learning setup, not hardened for public deployment.
