# tg-channel-aggregator

app to filter and aggregate content from multiple channels to single

```shell
VER=$(poetry version --short) docker buildx bake --progress=plain tg-channel-aggregator
```
```shell
export API_HASH=
export API_ID=
export BOT_TOKEN=
export OWNER_USER_ID=
docker run --rm -d --name "tg-channel-aggregator" -v "./data:/app/data" --env API_HASH --env API_ID --env BOT_TOKEN --env OWNER_USER_ID "tg-channel-aggregator:$(poetry version --short)"
```
```shell
docker save "tg-channel-aggregator:$(poetry version --short)" > "tg-channel-aggregator_$(poetry version --short)".tar
```
