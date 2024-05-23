# Generated by the Protocol Buffers compiler. DO NOT EDIT!
# source: snapshotter/utils/models/proto/snapshot_submission/submission.proto
# plugin: grpclib.plugin.main
import abc
import typing

import grpclib.client
import grpclib.const
if typing.TYPE_CHECKING:
    import grpclib.server

import snapshotter.utils.models.proto.snapshot_submission.submission_pb2


class SubmissionBase(abc.ABC):

    @abc.abstractmethod
    async def SubmitSnapshotSimulation(self, stream: 'grpclib.server.Stream[snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission, snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse]') -> None:
        pass

    @abc.abstractmethod
    async def SubmitSnapshot(self, stream: 'grpclib.server.Stream[snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission, snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse]') -> None:
        pass

    def __mapping__(self) -> typing.Dict[str, grpclib.const.Handler]:
        return {
            '/submission.Submission/SubmitSnapshotSimulation': grpclib.const.Handler(
                self.SubmitSnapshotSimulation,
                grpclib.const.Cardinality.STREAM_STREAM,
                snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission,
                snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse,
            ),
            '/submission.Submission/SubmitSnapshot': grpclib.const.Handler(
                self.SubmitSnapshot,
                grpclib.const.Cardinality.STREAM_UNARY,
                snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission,
                snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse,
            ),
        }


class SubmissionStub:

    def __init__(self, channel: grpclib.client.Channel) -> None:
        self.SubmitSnapshotSimulation = grpclib.client.StreamStreamMethod(
            channel,
            '/submission.Submission/SubmitSnapshotSimulation',
            snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission,
            snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse,
        )
        self.SubmitSnapshot = grpclib.client.StreamUnaryMethod(
            channel,
            '/submission.Submission/SubmitSnapshot',
            snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SnapshotSubmission,
            snapshotter.utils.models.proto.snapshot_submission.submission_pb2.SubmissionResponse,
        )
