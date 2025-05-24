# Knowledge Harvester

This project is a multi-component application designed for knowledge harvesting, featuring a data gathering engine, a FastAPI backend, and a Next.js frontend.

## Monorepo Structure

- **/engine/**: Python Poetry package for data gathering (custom implementation).
- **/api/**: FastAPI backend (Python Poetry package) with SQLAlchemy, Alembic, and Celery.
- **/web/**: Next.js 14 frontend (TypeScript, Tailwind CSS, shadcn/ui).
- **/infra/**: Docker Compose setup for all services.

## Quick Start

This section outlines how to get the project running locally using Docker.

### Prerequisites

- Docker (with Docker Compose V2 support)
- Git (for cloning, if you haven't already)
- A `.env` file in the `/api` directory if specific environment variables are needed beyond defaults provided in `docker-compose.yml` (e.g., `DEEPSEEK_API_KEY` for later phases). For baseline startup, defaults should suffice.

### Running the Application

1.  **Clone the repository (if you haven't already):**
    ```bash
    # git clone <repository-url>
    # cd knowledge-harvester
    ```

2.  **Navigate to the infrastructure directory:**
    ```bash
    cd infra
    ```

3.  **Build and start all services:**
    ```bash
    docker-compose up --build -d
    ```
    The `-d` flag runs the services in detached mode. Omit it if you want to see logs directly in your terminal.

4.  **Accessing the services:**
    - **Web Interface**: [http://localhost:3000](http://localhost:3000)
    - **API Ping Endpoint**: [http://localhost:8000/ping](http://localhost:8000/ping)
    - **API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
    - **PostgreSQL Database**: Connect on port `5432` (e.g., with `psql` or a GUI tool) using credentials `user:password` for database `knowledge_harvester_db`.
    - **Redis**: Connect on port `6379`.

### Stopping the Application

1.  **If running in detached mode (`-d`):**
    ```bash
    cd infra # (if not already there)
    docker-compose down
    ```

2.  **If running in the foreground (logs attached):**
    Press `Ctrl+C` in the terminal where `docker-compose up` is running, then run:
    ```bash
    cd infra # (if not already there)
    docker-compose down
    ```
    The `docker-compose down` command stops and removes the containers, networks, and optionally volumes (if specified).

## Development

- Python 3.11 for `/engine` and `/api`.
- Node.js 20 for `/web`.
- Pre-commit hooks are configured for linting and formatting. Install and set them up:
  ```bash
  pip install pre-commit
  pre-commit install
  ```

## Next Steps

Refer to the project's issue tracker and further documentation (once developed) for more detailed information on specific components and development workflows.
