# CyValidator Lab Environment

This folder contains isolated demo lab cases for CyValidator.

The lab is designed for defensive validation, demo scenarios and local testing only.

## Important Safety Notes

The lab cases simulate risky security conditions in a controlled way.

Do not deploy this lab to production.

Do not expose lab ports to the Internet.

The lab is intended to run locally on Windows with Docker Desktop.

## Run Lab

From the project root:

```bash
docker compose -f lab/docker-compose.lab.yml up --build