FROM python:3.13.3-slim-bookworm as build

ENV PYTHONUNBUFFERED 1
WORKDIR /usr/app
RUN python -m venv /usr/app/venv
#ensures that python and pip executables used in image will be from our virtual env created!
ENV PATH="/usr/app/venv/bin:$PATH"
COPY ["requirements.txt", "./"]
RUN pip install -r requirements.txt --no-cache-dir

FROM python:3.13.3-slim-bookworm as runner
RUN groupadd -g 990 ti-runner && useradd -r -u 990 -g ti-runner ti-runner
WORKDIR /usr/app
COPY --from=build /usr/app/venv ./venv
COPY --chown=ti-runner:ti-runner ./code ./code
ENV PATH="/usr/app/venv/bin:$PATH"
ENV PYTHONPATH="/usr/app"
USER ti-runner
ENTRYPOINT [ "python", "-m", "code.main" ]
