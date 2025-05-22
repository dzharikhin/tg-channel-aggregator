# tg-channel-aggregator

app to filter and aggregate content from multiple channels to single
## Build
> requires installed [poetry](https://python-poetry.org/)

```shell
VER=$(poetry version --short) docker buildx bake --progress=plain tg-channel-aggregator
```
## Run
```shell
API_HASH= API_ID= BOT_TOKEN= OWNER_USER_ID= docker run --rm -d --restart unless-stopped --name "tg-channel-aggregator" -v "./data:/app/data" --env API_HASH --env API_ID --env BOT_TOKEN --env OWNER_USER_ID "tg-channel-aggregator:$(poetry version --short)"
```
## Export
```shell
docker save "tg-channel-aggregator:$(poetry version --short)" > "tg-channel-aggregator_$(poetry version --short)".tar
```
