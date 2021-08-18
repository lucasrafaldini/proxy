FROM python:3

WORKDIR /opt/proxy
ENV WORKDIR=/opt/proxy
ENV PYTHONPATH=/opt/proxy:$PYTHONPATH
ENV PYTHONUNBUFFERED 1

# Copy project
COPY ./ /opt/proxy

# Copy ENV file
COPY ./.env /opt/proxy/.env

# Activate .env
CMD ["source", "/opt/proxy/.env"]

# Cache dependencies list
COPY ./requirements.txt ./requirements.txt

# Install dependencies
RUN pip install -r requirements.txt
