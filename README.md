# HiringRadar — Hiring Market Intelligence Dashboard

HiringRadar is a production-ready hiring intelligence dashboard that aggregates real-time job market data and presents it through a secure, backend-first architecture. Instead of showing raw job listings, HiringRadar focuses on **signals, trends, and demand patterns** in the hiring market.

🔗 **Live Demo:** https://hiringradar.onrender.com/  
🔗 **Portfolio:** https://devak-portfolio.netlify.app/

---

## Overview

Most job boards display postings. **HiringRadar analyzes hiring behavior.**

This project was built to simulate real-world backend systems by emphasizing authentication, API aggregation, caching, and production deployment—without frontend shortcuts or scraping hacks.

---

## Features

- **OAuth 2.0 Authentication**
  - Secure login flow
  - Server-side session handling
  - Protected API routes

- **Hiring Market Intelligence**
  - Aggregates external hiring APIs (e.g., USAJOBS)
  - Normalizes and enriches job market data
  - Surfaces demand trends instead of raw listings

- **Backend-First Design**
  - No client-side API key exposure
  - All third-party API calls handled on the server

- **Caching & Performance**
  - Intelligent caching to reduce redundant requests
  - Rate-limit aware API consumption

- **Production Deployment**
  - Deployed on Render
  - Environment-based configuration
  - Health-checked backend services

---

## Tech Stack

**Backend**
- Node.js
- Express.js
- OAuth 2.0
- REST APIs
- Server-side sessions

**Infrastructure**
- Render
- Environment variables for secrets management

---

## Architecture

Client
↓
Express Server
↓
OAuth 2.0 Authentication
↓
API Aggregation & Caching Layer
↓
External Hiring APIs (USAJOBS, etc.)


All authentication logic, API keys, and data processing remain securely on the backend.

---

## What This Project Demonstrates

- Secure backend service design
- External API integration under real-world constraints
- Backend systems beyond CRUD
- Caching and performance optimization
- Production deployment and operational awareness

HiringRadar was built to reflect how real hiring platforms and internal dashboards are engineered—not tutorial-style projects.

---

## Roadmap

- Role-based access control
- Historical hiring trend analytics
- Saved searches and alerts
- Employer-level insights
- Expanded data sources

---

## Author

**Devak Mehta**  
Computer Science @ Queens College (CUNY)  
Backend / Full-Stack Developer  

🔗 Portfolio: https://devak-portfolio.netlify.app/

---
