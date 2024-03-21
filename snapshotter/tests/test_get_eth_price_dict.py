import asyncio

from snapshotter.utils.snapshot_utils import get_eth_price_usd
from snapshotter.utils.rpc import RpcHelper
from snapshotter.utils.default_logger import logger
from snapshotter.settings.config import settings


async def test_get_eth_price_dict():
    
    from_block = 12084850
    to_block = from_block + 9
    rpc_helper = RpcHelper(rpc_settings=settings.rpc)
    await rpc_helper.init()
    
    price_dict = await get_eth_price_usd(
        from_block=from_block,
        to_block=to_block,
        rpc_helper=rpc_helper,
    )
    
    from pprint import pprint
    pprint(price_dict)

if __name__ == '__main__':
    try:
        asyncio.get_event_loop().run_until_complete(test_get_eth_price_dict())
    except Exception as e:
        print(e)
        logger.opt(exception=True).error('exception: {}', e)
