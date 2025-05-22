variable "VER" {}
target "tg-channel-aggregator" {
    context = "."
    dockerfile = "Dockerfile"
    tags = [ "tg-channel-aggregator:${VER}" ]
    output = [{ type = "docker" }]
}