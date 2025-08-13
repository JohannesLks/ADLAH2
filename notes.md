# Notes

## Push to docker hub
1. `docker login`
2. `docker tag hive-logstash:latest lukasjohannes/adlah-hive-logstash:latest`
3. `docker push lukasjohannes/adlah-hive-logstash:latest`
## Build PNG drom mermaid
1. `PUPPETEER_EXECUTABLE_PATH=/home/johannes/.cache/puppeteer/chrome/linux-139.0.7258.66/chrome-linux64/chrome npx --yes @mermaid-js/mermaid-cli -i The-Paper/src/final_architecture.mmd -o The-Paper/src/final_architecture.png -s 5 -t neutral -b transparent`