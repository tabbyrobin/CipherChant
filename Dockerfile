# https://stackoverflow.com/questions/53835198/integrating-python-poetry-with-docker/54763270#54763270
# FROM python:3.7
FROM debian:10
RUN apt-get update && apt-get install -y apt-utils && apt-get upgrade -y \
    && apt-get install -y \
    git \
    python-pip \
    # python2-pip \
    python3-pip \
    rsync \
    && rm -rf /var/lib/apt/lists/*

ARG YOUR_ENV # ARG YOUR_ENV=production
ENV YOUR_ENV=${YOUR_ENV} \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=1.1.3

# Having recent pip fixes some wheel not supported errors (e.g. for
# poetry installing regex module wheel).
RUN pip2 install --upgrade pip  &&  pip3 install --upgrade pip

# System deps:
RUN pip3 install "poetry==$POETRY_VERSION"

# Copy only requirements to cache them in docker layer
WORKDIR /code
COPY poetry.lock pyproject.toml /code/
# Project initialization:
RUN poetry install $(test "$YOUR_ENV" = production && echo "--no-dev") --no-interaction --no-ansi

# Get bananaphone module installed (requires python2)
COPY dependencies.sh /code/
RUN bash /code/dependencies.sh && rm -rf /var/lib/apt/lists/*

# Creating folders, and files for a project:
COPY . /code
# 2nd poetry-install to install my own project module:
RUN poetry install $(test "$YOUR_ENV" = production && echo "--no-dev") --no-interaction --no-ansi

# CMD ["poetry", "run", "pytest", "-s"]
CMD ["tail", "-f", "/dev/null"] # to keep container running
CMD while true ; do rsync -a --delete /vagrant/ /code/ ; sleep 2 ; done
