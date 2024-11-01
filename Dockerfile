FROM python:3.11-slim-bookworm as build

ENV PYTHONUNBUFFERED 1
WORKDIR /usr/app
RUN python -m venv /usr/app/venv
#ensures that python and pip executables used in image will be from our virtual env created!
ENV PATH="/usr/app/venv/bin:$PATH"
COPY ["requirements.txt", "./"]
RUN pip install -r requirements.txt --no-cache-dir

FROM python:3.11-slim-bookworm as runner
RUN groupadd -g 1000 ti-runner && useradd -r -u 1000 -g ti-runner ti-runner
WORKDIR /usr/app/venv
RUN chown ti-runner:ti-runner /usr/app/venv
COPY --chown=ti-runner:ti-runner --from=build /usr/app/venv ./
COPY --chown=ti-runner:ti-runner ["./code", "./"]
ENV PATH="/usr/app/venv/bin:$PATH"
USER ti-runner
ENTRYPOINT [ "python", "./main.py"]
