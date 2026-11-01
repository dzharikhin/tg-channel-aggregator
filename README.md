# tg-channel-aggregator

app to filter and aggregate content from multiple channels to single

## Dev environment
> requires installed [poetry](https://python-poetry.org/), python 3.14

```shell
poetry install
poetry run pytest
poetry run ruff check .
poetry run black .
```

## Build
> requires installed [poetry](https://python-poetry.org/)

```shell
VER=$(poetry version --short) docker buildx bake --progress=plain tg-channel-aggregator
```
## Run
```shell
API_HASH= API_ID= BOT_TOKEN= OWNER_USER_ID= docker run -d --restart unless-stopped --name "tg-channel-aggregator" -v "./data:/app/data" --env API_HASH --env API_ID --env BOT_TOKEN --env OWNER_USER_ID --memory=1G  --cpus=2 "tg-channel-aggregator:$(poetry version --short)"
```
## Export
```shell
docker save "tg-channel-aggregator:$(poetry version --short)" > "tg-channel-aggregator_$(poetry version --short)".tar
```
