ARG IMAGE_VERSION
FROM docker.io/datawire/aes:${IMAGE_VERSION}
ARG FILENAME_ROOT_CA
USER root
COPY ./${FILENAME_ROOT_CA} /usr/local/share/ca-certificates/${FILENAME_ROOT_CA}
RUN update-ca-certificates
USER 1000