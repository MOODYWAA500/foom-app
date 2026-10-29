# FOAM car wash

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env`, set DATABASE_URL and ADMIN_PASSWORD
3. `npm start`  ->  http://localhost:3000

## Deploy on Vercel
1. Push this folder to GitHub (the .env file is ignored, never upload it).
2. Vercel -> Add New Project -> import the repo (Framework preset: Other).
3. Settings -> Environment Variables: add DATABASE_URL and ADMIN_PASSWORD, then Redeploy.
Pages: / (customers) · /admin.html (admin) · /driver.html (driver PWA)
