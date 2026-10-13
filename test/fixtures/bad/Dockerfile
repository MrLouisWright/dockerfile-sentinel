FROM node:16
MAINTAINER someone@example.com
ARG NPM_TOKEN
ENV DB_PASSWORD=hunter2hunter2 \
    NODE_ENV=production
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl sudo openssh-server
RUN curl -fsSL https://get.example.sh | bash
RUN curl -k https://internal.example.com/x -o /x && chmod 777 /x
ADD http://downloads.example.com/tool.tar.gz /opt/
ADD app.js /app/
COPY . /app
COPY .env /app/.env
EXPOSE 22 8080
CMD ["node", "/app/app.js"]
