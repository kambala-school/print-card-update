# syntax=docker/dockerfile:1
FROM python:3.9.19-slim-bullseye
RUN pip install flask ldap3 python-dotenv
COPY app .
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]