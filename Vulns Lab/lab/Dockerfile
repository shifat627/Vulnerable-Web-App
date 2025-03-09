FROM python:3.12.3
WORKDIR /app
COPY . .
RUN mkdir -p /var/www/html
RUN pip3 install -r requirement.txt
RUN apt update -y && apt install openssh-server -y
EXPOSE 80
EXPOSE 22
CMD [ "bash","init.sh" ]
