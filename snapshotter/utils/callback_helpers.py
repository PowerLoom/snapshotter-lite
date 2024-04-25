import asyncio
import functools
from abc import ABC
from abc import ABCMeta
from abc import abstractmethod
from urllib.parse import urljoin

from httpx import AsyncClient
from httpx import Client as SyncClient
from ipfs_client.main import AsyncIPFSClient
from pydantic import BaseModel

from snapshotter.settings.config import settings
from snapshotter.utils.default_logger import logger
from snapshotter.utils.models.data_models import TelegramEpochProcessingReportMessage
from snapshotter.utils.models.data_models import TelegramSnapshotterReportMessage
from snapshotter.utils.models.data_models import SnapshotterReportData
from snapshotter.utils.models.data_models import EpochProcessingIssue
from snapshotter.utils.models.message_models import EpochBase
from snapshotter.utils.models.message_models import SnapshotProcessMessage
from snapshotter.utils.rpc import RpcHelper

# setup logger
helper_logger = logger.bind(module='Callback|Helpers')


def misc_notification_callback_result_handler(fut: asyncio.Future):
    """
    Handles the result of a callback or notification.

    Args:
        fut (asyncio.Future): The future object representing the callback or notification.

    Returns:
        None
    """
    try:
        r = fut.result()
    except Exception as e:
        if settings.logs.trace_enabled:
            logger.opt(exception=True).error(
                'Exception while sending callback or notification: {}', e,
            )
        else:
            logger.error('Exception while sending callback or notification: {}', e)
    else:
        logger.debug('Callback or notification result:{}', r)


def sync_notification_callback_result_handler(f: functools.partial):
    """
    Handles the result of a synchronous notification callback.

    Args:
        f (functools.partial): The function to handle.

    Returns:
        None
    """
    try:
        result = f()
    except Exception as exc:
        if settings.logs.trace_enabled:
            logger.opt(exception=True).error(
                'Exception while sending callback or notification: {}', exc,
            )
        else:
            logger.error('Exception while sending callback or notification: {}', exc)
    else:
        logger.debug('Callback or notification result:{}', result)


async def send_failure_notifications_async(client: AsyncClient, message: SnapshotterReportData):
    """
    Sends failure notifications to the configured reporting services.

    Args:
        client (AsyncClient): The async HTTP client to use for sending notifications.
        message (SnapshotterReportData): The message to send as notification.

    Returns:
        None
    """
    
    if settings.reporting.service_url:
        f = asyncio.ensure_future(
            client.post(
                url=urljoin(settings.reporting.service_url, '/reportIssue'),
                json=message.snapshotterIssue.dict(),
            ),
        )
        f.add_done_callback(misc_notification_callback_result_handler)

    if settings.reporting.slack_url:
        f = asyncio.ensure_future(
            client.post(
                url=settings.reporting.slack_url,
                json=message.snapshotterIssue.dict(),
            ),
        )
        f.add_done_callback(misc_notification_callback_result_handler)

    if settings.reporting.telegram_url and settings.reporting.telegram_chat_id:
        reporting_message = TelegramSnapshotterReportMessage(
            chatId=settings.reporting.telegram_chat_id,
            slotId=settings.slot_id,
            issue=message.snapshotterIssue,
            status=message.snapshotterStatus,
        )
        
        f = asyncio.ensure_future(
            client.post(
                url=urljoin(settings.reporting.telegram_url, '/reportSnapshotIssue'),
                json=reporting_message.dict(),
            ),
        )
        f.add_done_callback(misc_notification_callback_result_handler)


def send_failure_notifications_sync(client: SyncClient, message: SnapshotterReportData):
    """
    Sends failure notifications synchronously to to the configured reporting services.

    Args:
        client (SyncClient): The HTTP client to use for sending notifications.
        message (SnapshotterReportData): The message to send as notification.

    Returns:
        None
    """
    if settings.reporting.service_url:
        f = functools.partial(
            client.post,
            url=urljoin(settings.reporting.service_url, '/reportIssue'),
            json=message.snapshotterIssue.dict(),
        )
        sync_notification_callback_result_handler(f)

    if settings.reporting.slack_url:
        f = functools.partial(
            client.post,
            url=settings.reporting.slack_url,
            json=message.snapshotterIssue.dict(),
        )
        sync_notification_callback_result_handler(f)

    if settings.reporting.telegram_url and settings.reporting.telegram_chat_id:
        reporting_message = TelegramSnapshotterReportMessage(
            chatId=settings.reporting.telegram_chat_id,
            slotId=settings.slot_id,
            issue=message.snapshotterIssue,
            status=message.snapshotterStatus,
        )

        f = functools.partial(
            client.post,
            url=urljoin(settings.reporting.telegram_url, '/reportSnapshotIssue'),
            json=reporting_message.dict(),
        )
        sync_notification_callback_result_handler(f)


async def send_epoch_processing_failure_notification_async(client: AsyncClient, message: EpochProcessingIssue):
    """
    Sends epoch processing failure notifications synchronously to the telegarm reporting service.

    Args:
        client (SyncClient): The HTTP client to use for sending notifications.
        message (EpochProcessingIssue): The message to send as notification.

    Returns:
        None
    """
    if settings.reporting.telegram_url and settings.reporting.telegram_chat_id:
        reporting_message = TelegramEpochProcessingReportMessage(
            chatId=settings.reporting.telegram_chat_id,
            slotId=settings.slot_id,
            issue=message,
        )

        f = asyncio.ensure_future(
                client.post(
                    url=urljoin(settings.reporting.telegram_url, '/reportEpochProcessingIssue'),
                    json=reporting_message.dict(),
                ),
            )
        f.add_done_callback(misc_notification_callback_result_handler)


def send_epoch_processing_failure_notification_sync(client: SyncClient, message: EpochProcessingIssue):
    """
    Sends epoch processing failure notifications synchronously to the telegarm reporting service.

    Args:
        client (SyncClient): The HTTP client to use for sending notifications.
        message (EpochProcessingIssue): The message to send as notification.

    Returns:
        None
    """
    if settings.reporting.telegram_url and settings.reporting.telegram_chat_id:
        reporting_message = TelegramEpochProcessingReportMessage(
            chatId=settings.reporting.telegram_chat_id,
            slotId=settings.slot_id,
            issue=message,
        )

        f = functools.partial(
                client.post,
                url=urljoin(settings.reporting.telegram_url, '/reportEpochProcessingIssue'),
                json=reporting_message.dict(),
            )
        sync_notification_callback_result_handler(f)


class GenericProcessor(ABC):
    __metaclass__ = ABCMeta

    def __init__(self):
        pass

    @abstractmethod
    async def compute(
        self,
        msg_obj: SnapshotProcessMessage,
        rpc_helper: RpcHelper,
        anchor_rpc_helper: RpcHelper,
        ipfs_reader: AsyncIPFSClient,
        protocol_state_contract,
        eth_price_dict: dict,
    ):
        pass
