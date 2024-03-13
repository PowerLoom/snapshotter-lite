from snapshotter.settings.config import settings
from snapshotter.utils.default_logger import logger

from snapshotter.utils.rpc import RpcHelper


snapshot_util_logger = logger.bind(module='Powerloom|Snapshotter|SnapshotUtilLogger')



async def get_block_details_in_block_range(
    from_block,
    to_block,
    rpc_helper: RpcHelper,
):
    """
    Fetches block details for a given range of block numbers.

    Args:
        from_block (int): The starting block number.
        to_block (int): The ending block number.
        redis_conn (aioredis.Redis): The Redis connection object.
        rpc_helper (RpcHelper): The RPC helper object.

    Returns:
        dict: A dictionary containing block details for each block number in the given range.
    """
    try:


        # check if we have cached value for each block number

        rpc_batch_block_details = await rpc_helper.batch_eth_get_block(from_block, to_block)

        rpc_batch_block_details = (
            rpc_batch_block_details if rpc_batch_block_details else []
        )

        block_details_dict = dict()

        block_num = from_block
        for block_details in rpc_batch_block_details:
            block_details = block_details.get('result')
            # right now we are just storing timestamp out of all block details,
            # edit this if you want to store something else
            block_details = {
                'timestamp': int(block_details.get('timestamp', None), 16),
                'number': int(block_details.get('number', None), 16),
                'transactions': block_details.get('transactions', []),
            }

            block_details_dict[block_num] = block_details
            block_num += 1

        # add new block details and prune all block details older than latest 3 epochs

        return block_details_dict

    except Exception as e:
        snapshot_util_logger.opt(exception=settings.logs.trace_enabled, lazy=True).trace(
            'Unable to fetch block details, error_msg:{err}',
            err=lambda: str(e),
        )

        raise e


