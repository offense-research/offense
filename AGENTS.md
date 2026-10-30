# Repository Guidelines

## Project Structure & Module Organization

This repository contains the Offense security app, with legacy Purple identifiers retained for compatibility.

- `src/`: React components, UI helpers, and CSS; `public/`: static assets and distributed skills.
- `server/`: Express API and backend services; `shared/`: logic reused across runtimes.
- `workers/`: Cloudflare Workers, Durable Object integration, and container orchestration; `agent/`: isolated scanner and remediation runtimes.
- `scripts/`: builds, operations, CLI entry points, and integration checks; `sdk/` and `cli/`: distributable clients.
- `test/`: automated tests, `fixtures/`, and `helpers/`; `migrations/`: numbered SQL migrations; `docs/`: architecture and operations guides.
- `offense/`: separate package with its own manifest and contributor documentation.

## Build, Test, and Development Commands

Use Node.js 24 or newer and npm from the repository root.

- `npm ci`: install dependencies from `package-lock.json`.
- `npm run dev`: start Vite at `http://localhost:5173` and the watched API on port 3217.
- `npm run build`: build downloadable skills, the agent SDK, and frontend assets.
- `npm start`: serve the API and built app on port 3217.
- `npm test`: run the Node test suite.
- `npm run build:worker`: prepare Cloudflare deployment artifacts.

## Coding Style & Naming Conventions

Use ES modules, two-space indentation, single-quoted JavaScript strings, and semicolons, matching neighboring files. Name React components in PascalCase (`DependencyExplorer.jsx`), functions and variables in camelCase, and service/helper files in kebab-case (`dependency-graph.js`). Keep reusable cross-runtime logic in `shared/`. No root ESLint or Prettier configuration is present; follow existing conventions.

## Testing Guidelines

Tests use `node:test` and `node:assert/strict`, with names matching `test/*.test.js`. Run a focused check with `node --test test/dependency-graph.test.js`. Add regression coverage for behavior changes and reuse fixtures/helpers. CI requires `npm test` and `npm run build`; no numeric coverage threshold is configured. Scripts such as `npm run test:e2e` require private sessions and fixture configuration and may target live services; inspect their arguments before running.

## Commit & Pull Request Guidelines

Recent commits use short imperative subjects, such as “Report deduplicated advisory counts by GitHub repository owner.” Follow that style and keep commits focused. PRs should explain the problem, resulting behavior, and validation; link relevant issues and include screenshots for visible UI changes.

## Security & Configuration

Copy `.env.example` to `.env` and generate `ENCRYPTION_KEY` with `openssl rand -hex 32`. Keep credentials, session files, and local databases outside Git. Production secrets use Infisical; follow `docs/infisical.md` for deployment configuration.
