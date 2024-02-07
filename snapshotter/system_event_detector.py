import asyncio
import multiprocessing
import resource
import signal
import time
from signal import SIGINT
from signal import SIGQUIT
from signal import SIGTERM
import sys

from snapshotter.processor_distributor import ProcessorDistributor
from snapshotter.settings.config import settings
from snapshotter.utils.default_logger import logger
from snapshotter.utils.exceptions import GenericExitOnSignal
from snapshotter.utils.models.data_models import EpochReleasedEvent
from snapshotter.utils.rpc import RpcHelper


class EventDetectorProcess(multiprocessing.Process):

    def __init__(self, name, **kwargs):
        """
        Initializes the SystemEventDetector class.

        Args:
            name (str): The name of the process.
            **kwargs: Additional keyword arguments to be passed to the multiprocessing.Process class.

        Attributes:
            _shutdown_initiated (bool): A flag indicating whether shutdown has been initiated.
            _logger (logging.Logger): The logger instance.
            _last_processed_block (None): The last processed block.
            rpc_helper (RpcHelper): The RpcHelper instance.
            contract_abi (dict): The contract ABI.
            contract_address (str): The contract address.
            contract (web3.eth.Contract): The contract instance.
            event_sig (dict): The event signature.
            event_abi (dict): The event ABI.
        """
        multiprocessing.Process.__init__(self, name=name, **kwargs)
        self._shutdown_initiated = False
        self._logger = logger.bind(
            module=name,
        )

        self._last_processed_block = None
        self.rpc_helper = RpcHelper()

        self.processor_distributor = ProcessorDistributor()
        self._initialized = False

    async def init(self):
        await self.processor_distributor.init()

    async def get_events(self):
        """
        Retrieves events from the blockchain for the given block range and returns them as a list of tuples.
        Each tuple contains the event name and an object representing the event data.

        Args:
            from_block (int): The starting block number.
            to_block (int): The ending block number.

        Returns:
            List[Tuple[str, Any]]: A list of tuples, where each tuple contains the event name
            and an object representing the event data.
        """

        if not self._initialized:
            await self.init()
            self._initialized = True

        current_block_number = await self.rpc_helper.get_current_block()
        events = []

        event = EpochReleasedEvent(
            begin=current_block_number - 9,
            end=current_block_number,
            epochId=1,
            timestamp=int(time.time()),
        )

        events.append(("EpochReleased", event))

        self._logger.info('Events Detected: {}', events)
        return events

    def _generic_exit_handler(self, signum, sigframe):
        """
        Handles the generic exit signal and initiates shutdown.

        Args:
            signum (int): The signal number.
            sigframe (object): The signal frame.

        Raises:
            GenericExitOnSignal: If the shutdown is initiated.
        """
        if (
            signum in [SIGINT, SIGTERM, SIGQUIT] and
            not self._shutdown_initiated
        ):
            self._shutdown_initiated = True
            raise GenericExitOnSignal

    async def _detect_events(self):
        """
        Continuously detects events by fetching the current block and comparing it to the last processed block.
        If the last processed block is too far behind the current block, it processes the current block.
        """

        events = await self.get_events()

        for event_type, event in events:
            self._logger.info(
                'Processing event: {}', event,
            )
            _, status = await self.processor_distributor.process_event(
                event_type, event,
            )
            if status:
                self._logger.info(
                    '✅ Event processed successfully: {}!', event,
                )
                self._logger.info("Node is good to go, please wait for the full testnet to go live.")
            else:
                self._logger.error(
                    '❌ Event processing failed: {}.', event,
                )
                self._logger.info("Please check your config and if issue persists please reach out to the team!")
            sys.exit(0)

    def run(self):
        """
        A class for detecting system events.

        Methods:
        --------
        run()
            Starts the event detection process.
        """
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (settings.rlimit.file_descriptors, hard),
        )
        for signame in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
            signal.signal(signame, self._generic_exit_handler)

        self.ev_loop = asyncio.get_event_loop()
        self.ev_loop.run_until_complete(
            self._detect_events(),
        )

        # Define ANSI escape code for green color
        green_color = "\033[92m"
        # Reset color
        reset_color = "\033[0m"
        # Unicode character for check mark
        check_mark = "\u2713"
        # Print the green check mark
        self._logger.info(f"{green_color}{check_mark}: 'All Runs successful'{reset_color}")



if __name__ == '__main__':
    event_detector = EventDetectorProcess('EventDetector')
    event_detector.run()
