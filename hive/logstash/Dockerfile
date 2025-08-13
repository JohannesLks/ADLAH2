FROM docker.elastic.co/logstash/logstash:8.12.0
COPY dist/logstash.yml /usr/share/logstash/config/logstash.yml
COPY dist/pipelines/ /usr/share/logstash/pipeline/
USER root
USER logstash
