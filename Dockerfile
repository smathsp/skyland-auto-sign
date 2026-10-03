FROM ghcr.io/astral-sh/uv:python3.13-alpine

WORKDIR /app
COPY . .

RUN uv pip install --system -r requirements.txt
RUN mkdir -p logs

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV TOKEN=""
ENV BARK_KEY=""
ENV BARK_SERVER="https://api.day.app"

CMD ["python", "src/main.py" ]
