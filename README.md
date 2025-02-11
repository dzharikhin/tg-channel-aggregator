# tg-channel-aggregator

app to filter and aggregate content from multiple channels to single

```shell
export TG_AGGREGATOR_VERSION=
docker build -t "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}" .
docker buildx build --platform=linux/arm/v7 -t "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}-arm" .
```
```shell
export TG_AGGREGATOR_VERSION=
export API_HASH=
export API_ID=
export BOT_TOKEN=
export OWNER_USER_ID=
docker run --rm -d --name "tg-channel-aggregator" -v "./data:/app/data" --env API_HASH --env API_ID --env BOT_TOKEN --env OWNER_USER_ID "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}"
```
```shell
export TG_AGGREGATOR_VERSION=
docker save "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}" > "tg-channel-aggregator_${TG_AGGREGATOR_VERSION}".tar
docker save "tg-channel-aggregator:${TG_AGGREGATOR_VERSION}-arm" > "tg-channel-aggregator_${TG_AGGREGATOR_VERSION}-arm".tar
```
