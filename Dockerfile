# syntax=docker/dockerfile:1
FROM python:3.13-slim-bullseye
RUN pip install flask ldap3 python-dotenv
COPY app .
CMD ["python", "-u", "app.py"]