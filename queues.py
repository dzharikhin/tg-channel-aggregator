import functools

import persistqueue
import persistqueue.serializers.json

import config


@functools.cache
def get_or_create_sync_queue(user_id: int) -> persistqueue.SQLiteAckQueue:
    return persistqueue.SQLiteAckQueue(
        config.data_path.joinpath(str(user_id)),
        serializer=persistqueue.serializers.json,
        multithreading=True,
        auto_commit=True,
        db_file_name="queue.db",
    )
