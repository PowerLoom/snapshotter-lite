import asyncio
import json

from snapshotter.settings.config import settings
from snapshotter.utils.default_logger import logger
from snapshotter.utils.file_utils import read_json_file

from snapshotter.utils.rpc import get_contract_abi_dict
from snapshotter.utils.rpc import RpcHelper


snapshot_util_logger = logger.bind(module='Powerloom|Snapshotter|SnapshotUtilLogger')


TOKENS_DECIMALS = {
    'USDbC': 6,
    'DAI': 18,
    'USDC': 6,
    'WETH': 18,
}

# LOAD ABIs
pair_contract_abi = read_json_file(
    settings.pair_contract_abi,
    snapshot_util_logger,
)

# TODO: Move this to preloader config
DAI_WETH_PAIR = '0x93e8542E6CA0eFFfb9D57a270b76712b968A38f5'
USDC_WETH_PAIR = '0xd0b53D9277642d899DF5C87A3966A349A798F224'
USDbC_WETH_PAIR = '0x4C36388bE6F416A29C8d8Eee81C771cE6bE14B18'


def sqrtPriceX96ToTokenPrices(sqrtPriceX96, token0_decimals, token1_decimals):
    # https://blog.uniswap.org/uniswap-v3-math-primer

    price0 = ((sqrtPriceX96 / (2**96))** 2) / (10 ** token1_decimals / 10 ** token0_decimals)
    price1 = 1 / price0

    price0 = round(price0, token0_decimals)
    price1 = round(price1, token1_decimals)

    return price0, price1


async def get_eth_price_usd(
    from_block,
    to_block,
    rpc_helper: RpcHelper,
):
    try:
        eth_price_usd_dict = dict()

        pair_abi_dict = get_contract_abi_dict(pair_contract_abi)

        dai_eth_slot0_list = await rpc_helper.batch_eth_call_on_block_range(
            abi_dict=pair_abi_dict,
            function_name='slot0',
            contract_address=DAI_WETH_PAIR,
            from_block=from_block,
            to_block=to_block,
        )
        usdc_eth_slot0_list = await rpc_helper.batch_eth_call_on_block_range(
            abi_dict=pair_abi_dict,
            function_name='slot0',
            contract_address=USDC_WETH_PAIR,
            from_block=from_block,
            to_block=to_block,
        )
        usdbc_eth_slot0_list = await rpc_helper.batch_eth_call_on_block_range(
            abi_dict=pair_abi_dict,
            function_name='slot0',
            contract_address=USDbC_WETH_PAIR,
            from_block=from_block,
            to_block=to_block,
        )
        
        block_count = 0
        for block_num in range(from_block, to_block + 1):
            dai_eth_sqrt_price_x96 = dai_eth_slot0_list[block_count][0]
            usdc_eth_sqrt_price_x96 = usdc_eth_slot0_list[block_count][0]
            usdbc_eth_sqrt_price_x96 = usdbc_eth_slot0_list[block_count][0]
            # 1 dai / x ether  1 ether / x dai
            dai_eth_price, _ = sqrtPriceX96ToTokenPrices(
                sqrtPriceX96=dai_eth_sqrt_price_x96,
                token0_decimals=TOKENS_DECIMALS['WETH'],
                token1_decimals=TOKENS_DECIMALS['DAI'],

            )

            usdc_eth_price, _ = sqrtPriceX96ToTokenPrices(
                sqrtPriceX96=usdc_eth_sqrt_price_x96,
                token0_decimals=TOKENS_DECIMALS['WETH'],
                token1_decimals=TOKENS_DECIMALS['USDC'],

            )

            usdbc_eth_price, _ = sqrtPriceX96ToTokenPrices(
                sqrtPriceX96=usdbc_eth_sqrt_price_x96,
                token0_decimals=TOKENS_DECIMALS['WETH'],
                token1_decimals=TOKENS_DECIMALS['USDbC'],

            )

            # using fixed weightage for now, will use liquidity based weightage later
            # liquidity based weights will require fetching liquidity for each pair
            eth_price_usd = (dai_eth_price + usdc_eth_price + usdbc_eth_price) / 3
            eth_price_usd_dict[block_num] = float(eth_price_usd)
            block_count += 1

        return eth_price_usd_dict

    except Exception as err:
        snapshot_util_logger.opt(exception=settings.logs.trace_enabled).error(
            f'RPC ERROR failed to fetch ETH price, error_msg:{err}',
        )
        raise err


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


