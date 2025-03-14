FROM python:3.13.2@sha256:bc336add24c507d3a11b68a08fe694877faae3eab2d0e18b0653097f1a0db9f3

COPY /app/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt && rm -f requirements.txt

COPY /app /app
WORKDIR /app

CMD ["python3", "app.py"]
