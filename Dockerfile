FROM python:3.11-slim-bookworm as build

ENV PYTHONUNBUFFERED 1
WORKDIR /usr/app
RUN python -m venv /usr/app/venv
#ensures that python and pip executables used in image will be from our virtual env created
ENV PATH="/usr/app/venv/bin:$PATH"
COPY ["requirements.txt", "./"]
RUN pip install -r requirements.txt

FROM python:3.11-slim-bookworm as runner
RUN groupadd -g 8888 ti-runner && useradd -r -u 8877 -g ti-runner ti-runner
WORKDIR /usr/app/venv
RUN chown ti-runner:ti-runner /usr/app/venv
COPY --chown=ti-runner:ti-runner --from=build /usr/app/venv ./
COPY --chown=ti-runner:ti-runner ["./code", "./"]
ENV PATH="/usr/app/venv/bin:$PATH"
RUN set -ex \
    # Upgrade the package index and install security upgrades
    && apt-get update \
    && apt-get upgrade -y \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
USER ti-runner
ENTRYPOINT [ "python", "./ti-runner.py"]
