FROM python:3.12

ENV HOME /root

WORKDIR /root

COPY . .

# Download dependancies
RUN pip3 install  --no-cache-dir -r requirements.txt

EXPOSE 8080

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u server.py --host 0.0.0.0 --port 8080