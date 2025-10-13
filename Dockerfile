FROM debian:trixie

RUN apt-get update -y
RUN apt-get upgrade -y

RUN apt-get install -y dumb-init
RUN apt-get install -y build-essential

RUN apt-get clean -y

COPY ./run.sh /var/run.sh

ENTRYPOINT [ "/usr/bin/dumb-init", "--" ]
CMD [ "/bin/bash", "/var/run.sh" ]
