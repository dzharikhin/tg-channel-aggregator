# tg-channel-aggregator

app to filter and aggregate content from multiple channels to single

```shell
export TG_AGGREGATOR_VERSION=
docker build -t "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}" .
```
```shell
export API_HASH=
export API_ID=
export BOT_TOKEN=
export OWNER_USER_ID=
docker run --rm -d --name test -v "./data:/app/data" --env API_HASH --env API_ID --env BOT_TOKEN --env OWNER_USER_ID "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}"
```


