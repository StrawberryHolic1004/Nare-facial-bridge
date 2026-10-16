import ast
import atexit
import http.client
import io
import json
import logging
import math
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from pathlib import Path
from tkinter import filedialog, ttk

# 눈 좌우 지연 동기화와 카메라 회전·반전을 사용하려면 Pillow를 설치해야 한다:
#   py -m pip install pillow
try:
    from PIL import Image, ImageChops, ImageStat, ImageTk

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

# 앱 안에서 스트림을 구분하는 번호다. 패킷에 이 번호를 어떻게 넣을지는 encode_frame이 정한다.
CHANNEL_FACE, CHANNEL_LEFT, CHANNEL_RIGHT = 0, 1, 2
CHANNELS = (CHANNEL_FACE, CHANNEL_LEFT, CHANNEL_RIGHT)
EYE_CHANNELS = (CHANNEL_LEFT, CHANNEL_RIGHT)
APP_VERSION = "1.0.7"
DEFAULT_PORT = 0000
READ_TIMEOUT = 3.0
MAX_BUFFER_BYTES = 16 * 1024 * 1024
MOTION_HISTORY_SECONDS = 4.0
BG, PANEL, INSET, LINE = "#0c1119", "#141d29", "#0e1621", "#263344"
WHITE, MUTED, ACCENT = "#eef4fa", "#8c9eb3", "#ff8587"
CONTROL_BG, FIELD_BG, FIELD_ACTIVE = "#223044", "#243247", "#30435c"
ERROR_RED, READY_GREEN = "#ff4f5e", "#74e3c2"
FONT, LATIN_FONT = "맑은 고딕", "Segoe UI"
LOGGER = logging.getLogger("narebridge")

# 설정, 로그, 패킷 JSON은 실행 파일 옆에 저장한다. 스크립트로 실행하면 스크립트 옆에 저장한다.
APP_DIRECTORY = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)


def asset_path(name):
    # 사용자가 배너 이미지 등을 바꿔서 사용할 수 있도록 실행 파일 옆 assets 폴더의 파일을 먼저 찾는다.
    # 없으면 PyInstaller가 exe 안에 넣어 둔 기본 파일을 사용한다.
    for base in (APP_DIRECTORY, Path(getattr(sys, "_MEIPASS", APP_DIRECTORY))):
        path = base / "assets" / name

        if path.exists():
            return path

    return None


class DiagnosticQueueHandler(QueueHandler):
    def __init__(self, log_queue):
        super().__init__(log_queue)
        self.lost = 0

    def enqueue(self, record):
        try:
            # 대기열이 가득 차면 새 로그를 버리고 버린 개수만 센다.
            # 로그를 남기느라 영상 수신이나 전송이 멈추면 안 되기 때문이다.
            self.queue.put_nowait(record)
        except queue.Full:
            self.lost += 1


class DiagnosticQueueListener(QueueListener):
    def enqueue_sentinel(self):
        # 기본 구현(put_nowait)은 대기열이 가득 차면 종료 신호를 넣지 못하므로, 자리가 날 때까지 기다린다.
        self.queue.put(self._sentinel)


DIAGNOSTIC_LISTENER = None
DIAGNOSTIC_HANDLER = None


def configure_diagnostics():
    global DIAGNOSTIC_LISTENER, DIAGNOSTIC_HANDLER

    if DIAGNOSTIC_LISTENER is not None:
        return

    try:
        file_handler = RotatingFileHandler(
            APP_DIRECTORY / "bridge.log", maxBytes=8 * 1024 * 1024, backupCount=4, encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(message)s")
        )
        log_queue = queue.Queue(maxsize=4096)
        DIAGNOSTIC_HANDLER = DiagnosticQueueHandler(log_queue)
        LOGGER.addHandler(DIAGNOSTIC_HANDLER)
        LOGGER.setLevel(logging.INFO)
        LOGGER.propagate = False
        DIAGNOSTIC_LISTENER = DiagnosticQueueListener(log_queue, file_handler)
        DIAGNOSTIC_LISTENER.start()
        atexit.register(shutdown_diagnostics)
        LOGGER.info(
            "Application started version=%s pid=%s python=%s frozen=%s",
            APP_VERSION,
            os.getpid(),
            sys.version.split()[0],
            getattr(sys, "frozen", False),
        )
    except OSError:
        LOGGER.addHandler(logging.NullHandler())


def shutdown_diagnostics():
    global DIAGNOSTIC_LISTENER, DIAGNOSTIC_HANDLER

    if DIAGNOSTIC_LISTENER is not None:
        DIAGNOSTIC_LISTENER.stop()

        for handler in DIAGNOSTIC_LISTENER.handlers:
            handler.close()

        LOGGER.removeHandler(DIAGNOSTIC_HANDLER)
        DIAGNOSTIC_LISTENER = None
        DIAGNOSTIC_HANDLER = None


def diagnostic(event, level=logging.INFO, **details):
    LOGGER.log(level, "%s %s", event, json.dumps(details, ensure_ascii=False, default=str))


def write_json_atomic(path, data, prefix):
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=prefix, suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def validate_adapter_code(code):
    if not isinstance(code, str) or not code.strip():
        raise ValueError("패킷 코드가 비어 있습니다.")

    tree = ast.parse(code)
    compile(tree, "<packet-adapter>", "exec")

    if not any(binds_encode_frame(node) for node in tree.body):
        raise ValueError("encode_frame(channel, frame_id, jpeg_bytes) 함수를 정의하세요.")


def binds_encode_frame(node):
    # 코드를 실행하지 않고 검사하므로, 모듈 최상위에서 encode_frame을 def나 대입으로 정의했는지만 본다.
    # 호출할 수 있는지는 PacketAdapter가 코드를 실행한 뒤 확인하므로, lambda를 대입한 경우도 통과시킨다.
    if isinstance(node, ast.FunctionDef):
        return node.name == "encode_frame"

    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        targets = [node.target]
    else:
        return False

    return any(isinstance(target, ast.Name) and target.id == "encode_frame" for target in targets)


def read_adapter_file(path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("지원하지 않는 패킷 JSON 형식입니다. version: 1이 필요합니다.")

    code = data.get("code")

    if not isinstance(code, str):
        raise ValueError("JSON의 code는 문자열이어야 합니다.")

    if code.strip():
        validate_adapter_code(code)

    return code


def write_adapter_file(path, code):
    if code.strip():
        validate_adapter_code(code)

    data = {"version": 1, "name": "Custom UDP adapter", "code": code}
    write_json_atomic(path, data, ".packet-adapter-")


class SettingsStore:
    """settings.json을 읽고 저장한다. 저장에 실패하면 OSError가 그대로 전달되므로, 오류 안내는 호출하는 쪽에서 맡는다."""

    def __init__(self, path):
        self.path = path
        self.data = {}

        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8-sig"))

                if isinstance(data, dict):
                    self.data = data
        except (OSError, ValueError, UnicodeError):
            pass

    def get(self, key, default=None):
        return self.data.get(key, default)

    def save(self, **changes):
        data = {**self.data, **changes}
        write_json_atomic(self.path, data, ".bridge-settings-")
        self.data = data


AI_GUIDE = """CUSTOM UDP OUTPUT ADAPTER - IMPLEMENTATION CONTRACT
Write a Python module defining exactly:
    def encode_frame(channel: int, frame_id: int, jpeg_bytes: bytes) -> list[bytes]:
Input: channel 0 = face, 1 = left eye, 2 = right eye (internal labels only),
frame_id is a per-stream integer, jpeg_bytes contains one complete JPEG frame.
Output: an ordered list of fully encoded UDP datagrams as bytes.
Do not open sockets, sleep, write files or decode/re-encode the JPEG in this function.
The host app handles transmission, timing, synchronization, reconnect and UI.
Keep each datagram <= 65507 bytes (IPv4 UDP payload maximum); prefer smaller
payloads if your receiver or network requires it. Handle oversized JPEG frames.
Before streaming starts, the host app calls encode_frame(0, 0, b"\\xff\\xd8\\xff\\xd9")
once with a 4-byte placeholder JPEG to check the return type. It must return a
packet list for this input instead of raising, so do not reject small JPEG frames.
Provide clear validation and use standard-library modules when possible.
Implement only a protocol that the user owns, is authorized to implement,
or that has publicly documented specifications. Do not guess private formats.
Ask the AI assistant to implement this function from YOUR AUTHORIZED protocol
specification, and paste only the Python code into the editor above.
"""


class FrameTransforms:
    def __init__(self, saved=None):
        self.lock = threading.Lock()
        saved = saved if isinstance(saved, dict) else {}
        self.values = {}

        for channel in CHANNELS:
            value = saved.get(str(channel), {})
            value = value if isinstance(value, dict) else {}
            rotation = value.get("rotation", 0)

            if type(rotation) is not int or rotation not in (0, 90, 180, 270):
                rotation = 0

            self.values[channel] = (rotation, value.get("mirror", False) is True)

        if not PIL_AVAILABLE and any(value != (0, False) for value in self.values.values()):
            # Pillow가 없으면 회전·반전 버튼을 누를 수 없으므로, 저장된 값도 적용하지 않고 원본 그대로 보낸다.
            # 설정 파일의 값은 지우지 않으므로 Pillow를 설치하면 다시 적용된다.
            diagnostic("CAMERA_TRANSFORM_IGNORED", saved=self.to_settings())
            self.values = dict.fromkeys(CHANNELS, (0, False))

    def get(self, channel):
        with self.lock:
            return self.values[channel]

    def set(self, channel, rotation, mirror):
        with self.lock:
            self.values[channel] = (rotation, mirror)

    def to_settings(self):
        with self.lock:
            return {
                str(ch): {"rotation": rotation, "mirror": mirror}
                for ch, (rotation, mirror) in self.values.items()
            }

    def apply(self, channel, jpeg):
        rotation, mirror = self.get(channel)

        if rotation == 0 and not mirror:
            return jpeg

        with Image.open(io.BytesIO(jpeg)) as original:
            image = original.convert("RGB")

            if rotation:
                # 화면의 회전 버튼은 시계 방향이고 PIL의 ROTATE_*는 반시계 방향이라, 각도를 반대로 대응시킨다.
                operation = {
                    90: Image.Transpose.ROTATE_270,
                    180: Image.Transpose.ROTATE_180,
                    270: Image.Transpose.ROTATE_90,
                }[rotation]
                image = image.transpose(operation)

            if mirror:
                image = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)

            output = io.BytesIO()
            image.save(output, format="JPEG", quality=95, subsampling=0)
            return output.getvalue()


class TransformError(Exception):
    """카메라 회전·반전 중에 발생한 오류. 패킷 코드 오류와 구분해 표시하기 위해 사용한다."""


class UdpSendError(Exception):
    """UDP 전송 중에 발생한 OSError. 패킷 코드 오류와 구분해 표시하기 위해 사용한다."""


class PacketAdapter:
    def __init__(self, code, transforms=None):
        self.transforms = transforms
        self.code = code
        namespace = {"__name__": "user_packet_adapter"}

        # 사용자가 넣은 코드를 그대로 실행한다. 이 코드는 PC에서 아무 제한 없이 실행되므로,
        # 직접 작성했거나 출처를 믿을 수 있는 코드만 사용해야 한다.
        exec(compile(code, "<packet-adapter>", "exec"), namespace)
        encode_frame = namespace.get("encode_frame")

        if not callable(encode_frame):
            raise ValueError("encode_frame(channel, frame_id, jpeg_bytes) 함수를 정의하세요.")

        self.encode_frame = encode_frame

        # 얼굴 프레임과 눈 프레임을 보내는 작업이 encode_frame을 동시에 호출할 수 있다.
        # 잠금을 걸어 한 번에 하나씩만 실행하므로, 사용자 코드에서 전역 변수를 사용해도 값이 꼬이지 않는다.
        self.call_lock = threading.Lock()

    @staticmethod
    def validate_packet_list(packets):
        if not isinstance(packets, (list, tuple)):
            raise TypeError("encode_frame은 bytes 패킷의 목록을 반환해야 합니다.")

        if len(packets) > 65535:
            raise ValueError("한 프레임의 패킷 수가 너무 많습니다.")

    @staticmethod
    def validate_packet(packet):
        if not isinstance(packet, bytes) or not 0 < len(packet) <= 65507:
            raise ValueError("각 패킷은 bytes 형식이며 크기는 1~65507바이트여야 합니다.")

    @classmethod
    def validate_packets(cls, packets):
        cls.validate_packet_list(packets)

        for packet in packets:
            cls.validate_packet(packet)

    def send(self, sock, target, channel, frame_id, jpeg_bytes):
        if not jpeg_bytes:
            return 0

        started = time.monotonic()

        if self.transforms is not None:
            try:
                jpeg_bytes = self.transforms.apply(channel, jpeg_bytes)
            except Exception as exc:
                raise TransformError(exc) from exc

        transformed = time.monotonic()

        with self.call_lock:
            acquired = time.monotonic()
            packets = self.encode_frame(channel, frame_id, jpeg_bytes)

        encoded = time.monotonic()
        self.validate_packet_list(packets)

        # 패킷을 하나씩 검사하며 보낸다. 잘못된 패킷이 나오면 그 앞의 정상 패킷은 이미 보낸 상태로 오류를 낸다.
        for packet in packets:
            self.validate_packet(packet)

            try:
                sock.sendto(packet, target)
            except OSError as exc:
                raise UdpSendError(exc) from exc

        finished = time.monotonic()

        if finished - started >= 0.05:
            diagnostic(
                "SEND_SLOW",
                logging.WARNING,
                channel=channel,
                frame_id=frame_id,
                jpeg_bytes=len(jpeg_bytes),
                packets=len(packets),
                total_ms=round((finished - started) * 1000, 1),
                transform_ms=round((transformed - started) * 1000, 1),
                adapter_wait_ms=round((acquired - transformed) * 1000, 1),
                encode_ms=round((encoded - acquired) * 1000, 1),
                udp_ms=round((finished - encoded) * 1000, 1),
            )

        return len(packets)


@dataclass
class StreamStats:
    connected: bool = False
    frames: int = 0
    packets: int = 0
    last_frame_time: float = 0.0
    last_frame_size: int = 0
    error: str = ""
    received: int = 0
    dropped: int = 0


def record_sent_frame(stats, stats_lock, channel, packets, jpeg_size, sent_time=None):
    with stats_lock:
        st = stats[channel]
        st.frames += 1
        st.packets += packets

        if sent_time is not None:
            st.last_frame_time = sent_time

        st.last_frame_size = jpeg_size
        st.error = ""


# 채널별로 [마지막으로 남긴 오류, 남긴 시각, 그 뒤 건너뛴 횟수]를 저장한다.
_SEND_ERROR_LOG = {}
SEND_ERROR_LABELS = {TransformError: "카메라 회전·반전 오류", UdpSendError: "UDP 전송 오류"}


def record_send_error(stats, stats_lock, channel, frame_id, jpeg, exc):
    error, now = repr(exc), time.monotonic()
    label = SEND_ERROR_LABELS.get(type(exc), "패킷 코드 오류")

    with stats_lock:
        stats[channel].error = f"{label}: {exc}"

        # 전송에 계속 실패하면 프레임마다 같은 오류가 반복된다.
        # 새 오류는 바로 남기고, 같은 오류는 1초에 한 번만 남기면서 그동안 건너뛴 횟수를 함께 적는다.
        # 다른 오류로 바뀌면, 이전 오류를 건너뛴 횟수는 previous_suppressed로 남긴다.
        last = _SEND_ERROR_LOG.get(channel)
        same = last is not None and last[0] == error

        if same and now - last[1] < 1.0:
            last[2] += 1
            return

        suppressed = last[2] if same else 0
        previous_suppressed = last[2] if last is not None and not same else 0
        _SEND_ERROR_LOG[channel] = [error, now, 0]

    diagnostic(
        "SEND_ERROR",
        logging.ERROR,
        channel=channel,
        frame_id=frame_id,
        jpeg_bytes=len(jpeg),
        error=error,
        suppressed=suppressed,
        previous_suppressed=previous_suppressed,
    )


class EyeSynchronizer:
    """눈 움직임으로 좌우 영상의 도착 시차를 추정하고, 먼저 도착하는 쪽 눈만 늦춰 보낸다.
    delta_t > 0이면 오른쪽이 늦게 도착하므로 왼쪽을 delta_t만큼 늦춘다.
    delta_t < 0이면 왼쪽이 늦게 도착하므로 오른쪽을 -delta_t만큼 늦춘다.
    채널과 채널별 프레임 ID는 바꾸지 않는다. 회전·반전을 설정하지 않았다면 JPEG도 원본 그대로 보낸다.
    """

    def __init__(self, sock, target, stop_event, stats, stats_lock, adapter, enabled=True):
        self.sock, self.target = sock, target
        self.adapter = adapter
        self.stop_event = stop_event
        self.stats, self.stats_lock = stats, stats_lock
        self.enabled = enabled
        self.cv = threading.Condition()
        self.queues = {ch: deque() for ch in EYE_CHANNELS}
        self.histories = {ch: deque(maxlen=900) for ch in EYE_CHANNELS}
        self.prev_image = dict.fromkeys(EYE_CHANNELS)
        self.offset = 0.0  # delta_t: 같은 깜빡임이 오른쪽에 도착한 시각 - 왼쪽에 도착한 시각
        self.confidence = False
        self.last_calibrated_event = float("-inf")
        self.frame_ids = dict.fromkeys(EYE_CHANNELS, 0)
        self.dropped = 0
        self.analysis_queues = {ch: deque(maxlen=4) for ch in EYE_CHANNELS}

        # 채널별 (디코딩 실패 누계, 마지막으로 로그를 남긴 시각). 분석 스레드에서만 사용한다.
        self.decode_failures = dict.fromkeys(EYE_CHANNELS, (0, float("-inf")))
        self.analysis_ms = 0.0
        self.calibration_ms = 0.0

        # 보정을 초기화할 때마다 1씩 올린다.
        # 분석·보정 스레드는 작업하는 사이에 이 값이 바뀌었으면 결과를 버린다.
        self.calibration_generation = 0
        self.send_thread = threading.Thread(target=self._run, daemon=True, name="eye-delay")
        self.calibration_thread = threading.Thread(
            target=self._calibrate, daemon=True, name="eye-calibration"
        )
        self.analysis_thread = threading.Thread(
            target=self._analyze, daemon=True, name="eye-motion"
        )

    def start(self):
        self.analysis_thread.start()
        self.send_thread.start()
        self.calibration_thread.start()

    def threads(self):
        return (self.send_thread, self.calibration_thread, self.analysis_thread)

    def is_alive(self):
        return any(thread.is_alive() for thread in self.threads())

    def _calibrate(self):
        while not self.stop_event.is_set():
            started = time.perf_counter()
            self._estimate_offset()
            self.calibration_ms = (time.perf_counter() - started) * 1000
            self.stop_event.wait(0.5)

    def set_enabled(self, enabled):
        diagnostic("SYNC_CHANGED", enabled=bool(enabled))

        with self.cv:
            self.enabled = bool(enabled)
            self._reset_calibration(EYE_CHANNELS)

    def reset_channel(self, channel):
        with self.cv:
            diagnostic(
                "SYNC_RESET",
                channel=channel,
                queued_discarded=len(self.queues[channel]),
                offset_ms=round(self.offset * 1000, 1),
            )
            self.queues[channel].clear()
            self._reset_calibration((channel,))

    def _reset_calibration(self, channels):
        # self.cv 잠금을 건 상태에서 호출해야 한다.
        self.calibration_generation += 1
        self.offset = 0.0
        self.confidence = False
        self.last_calibrated_event = float("-inf")

        for channel in channels:
            self.analysis_queues[channel].clear()
            self.histories[channel].clear()
            self.prev_image[channel] = None

        self.cv.notify_all()

    def _analyze(self):
        # JPEG 디코딩은 이 스레드에서만 한다. 수신·전송 쪽은 JPEG를 디코딩하지 않고 그대로 넘긴다.
        while not self.stop_event.is_set():
            with self.cv:
                pending = [(q[0][0], ch) for ch, q in self.analysis_queues.items() if q]

                if not pending:
                    self.cv.wait(timeout=0.025)
                    continue

                _, channel = min(pending)
                timestamp, jpeg, generation = self.analysis_queues[channel].popleft()
                previous = self.prev_image[channel]

            started = time.perf_counter()

            try:
                with Image.open(io.BytesIO(jpeg)) as im:
                    # 처음부터 작은 흑백 이미지로 디코딩해서 분석 시간을 줄인다.
                    im.draft("L", (48, 32))
                    gray = im.resize((48, 32)).convert("L")

                motion = (
                    ImageStat.Stat(ImageChops.difference(gray, previous)).mean[0]
                    if previous is not None
                    else None
                )
            except Exception as exc:
                self._record_decode_failure(channel, exc)
                continue

            self.analysis_ms = (time.perf_counter() - started) * 1000

            with self.cv:
                if generation != self.calibration_generation or not self.enabled:
                    continue

                self.prev_image[channel] = gray

                if motion is not None:
                    history = self.histories[channel]
                    history.append((timestamp, motion))

                    while history and timestamp - history[0][0] > MOTION_HISTORY_SECONDS:
                        history.popleft()

    def _record_decode_failure(self, channel, exc):
        # 눈 JPEG가 계속 디코딩되지 않으면 보정이 끝나지 않는다. 로그가 프레임마다 쌓이지 않도록
        # 채널마다 5초에 한 번만 남기고, 실패 횟수는 누계로 적는다.
        count, last_logged = self.decode_failures[channel]
        count += 1
        now = time.monotonic()

        if now - last_logged >= 5.0:
            diagnostic(
                "EYE_DECODE_FAILED",
                logging.WARNING,
                channel=channel,
                count=count,
                error=repr(exc),
            )
            last_logged = now

        self.decode_failures[channel] = (count, last_logged)

    def add(self, channel, jpeg, timestamp):
        with self.cv:
            self.queues[channel].append((timestamp, jpeg))

            if PIL_AVAILABLE and self.enabled:
                self.analysis_queues[channel].append((timestamp, jpeg, self.calibration_generation))

            dropped = 0
            reasons = set()
            oldest_age = 0.0

            # 보정으로 늦추는 시간은 최대 0.3초다. 0.7초 넘게 기다린 프레임은 이미 늦었으므로 버리고,
            # 대기열은 512개까지만 둔다.
            while self.queues[channel] and (
                len(self.queues[channel]) > 512 or timestamp - self.queues[channel][0][0] > 0.7
            ):
                reasons.add("queue_limit" if len(self.queues[channel]) > 512 else "stale_frame")
                oldest_age = max(oldest_age, timestamp - self.queues[channel][0][0])
                self.queues[channel].popleft()
                dropped += 1

            if dropped:
                self._record_drops(
                    channel, dropped, "enqueue", sorted(reasons), oldest_age, self.offset
                )

            self.cv.notify_all()

    def _record_drops(self, channel, count, source, reasons, oldest_age, offset):
        # self.cv 잠금을 건 상태에서 호출해야 한다.
        self.dropped += count

        with self.stats_lock:
            self.stats[channel].dropped += count
            total = self.stats[channel].dropped

        diagnostic(
            "FRAME_DROP",
            logging.WARNING,
            channel=channel,
            source=source,
            count=count,
            reasons=reasons,
            oldest_ms=round(oldest_age * 1000, 1),
            remaining=len(self.queues[channel]),
            total=total,
            sync_enabled=self.enabled,
            offset_ms=round(offset * 1000, 1),
        )

    @staticmethod
    def _blink_candidates(samples):
        """짧은 움직임 봉우리 두 개를 깜빡임 후보로 본다. 눈을 떴는지 감았는지는 판단하지 않는다."""
        if len(samples) < 12:
            return []

        values = sorted(v for _, v in samples)
        baseline = values[len(values) // 2]
        deviations = sorted(abs(v - baseline) for v in values)
        mad = deviations[len(deviations) // 2]
        threshold = max(1.5, baseline + 3.5 * max(mad, 0.25))
        peaks = []

        for i in range(1, len(samples) - 1):
            t, value = samples[i]

            if value < threshold or value < samples[i - 1][1] or value < samples[i + 1][1]:
                continue

            if peaks and t - peaks[-1][0] < 0.09:
                if value > peaks[-1][1]:
                    peaks[-1] = (t, value)
            else:
                peaks.append((t, value))

        events = []

        for i in range(len(peaks) - 1):
            t1, a1 = peaks[i]
            t2, a2 = peaks[i + 1]
            duration = t2 - t1

            if not 0.10 <= duration <= 0.65:
                continue

            # 두 봉우리 사이에 큰 움직임이 또 있으면 깜빡임인지 확실하지 않으므로 버린다.
            intermediate = [v for t, v in samples if t1 + 0.08 < t < t2 - 0.08]

            if intermediate and max(intermediate) >= threshold:
                continue

            events.append((t1, t2, min(a1, a2)))

        return events

    @staticmethod
    def _local_correlation(left, right, lag, event_start):
        rt = [t for t, _ in right]
        rv = [v for _, v in right]
        pairs = []
        j = 0

        for t, v in left:
            if not event_start - 0.15 <= t <= event_start + 0.85:
                continue

            desired = t + lag

            while j + 1 < len(rt) and abs(rt[j + 1] - desired) < abs(rt[j] - desired):
                j += 1

            if abs(rt[j] - desired) <= 0.025:
                pairs.append((v, rv[j]))

        if len(pairs) < 9:
            return -1.0

        am = sum(a for a, _ in pairs) / len(pairs)
        bm = sum(b for _, b in pairs) / len(pairs)
        num = sum((a - am) * (b - bm) for a, b in pairs)
        den = (sum((a - am) ** 2 for a, _ in pairs) * sum((b - bm) ** 2 for _, b in pairs)) ** 0.5
        return num / den if den > 1e-8 else -1.0

    def _estimate_offset(self):
        # 양쪽 눈에서 믿을 만한 깜빡임을 찾지 못하면 이전 delta_t를 그대로 사용한다.
        if not PIL_AVAILABLE:
            return

        with self.cv:
            if not self.enabled:
                return

            generation = self.calibration_generation
            cutoff = time.monotonic() - MOTION_HISTORY_SECONDS
            left = [(t, v) for t, v in self.histories[CHANNEL_LEFT] if t >= cutoff]
            right = [(t, v) for t, v in self.histories[CHANNEL_RIGHT] if t >= cutoff]
            last_event = self.last_calibrated_event
            confidence, offset = self.confidence, self.offset

        if len(left) < 12 or len(right) < 12:
            return

        left_events = self._blink_candidates(left)
        right_events = self._blink_candidates(right)

        if not left_events or not right_events:
            return

        matches = []

        for left_start, left_end, left_strength in left_events:
            if left_start <= last_event:
                continue

            for right_start, right_end, right_strength in right_events:
                start_lag, end_lag = right_start - left_start, right_end - left_end

                if max(abs(start_lag), abs(end_lag)) > 0.30:
                    continue

                if abs(start_lag - end_lag) > 0.065:
                    continue

                lag = (start_lag + end_lag) / 2

                if confidence and abs(lag - offset) > 0.15:
                    continue

                score = self._local_correlation(left, right, lag, left_start)

                if score < 0.65:
                    continue

                matches.append((score, min(left_strength, right_strength), lag, left_start))

        if not matches:
            return

        matches.sort(reverse=True)
        score, _strength, lag, event_time = matches[0]

        with self.cv:
            if generation != self.calibration_generation or not self.enabled:
                return

            # 첫 보정값은 바로 사용하고, 그 뒤로는 한 번에 최대 9ms씩만 움직여 값이 갑자기 튀지 않게 한다.
            if not self.confidence:
                self.offset = lag
            else:
                step = max(-0.03, min(0.03, lag - self.offset))
                self.offset += 0.3 * step

            self.offset = max(-0.3, min(0.3, self.offset))
            self.last_calibrated_event = event_time
            self.confidence = True
            diagnostic(
                "SYNC_CALIBRATED",
                offset_ms=round(self.offset * 1000, 2),
                candidate_ms=round(lag * 1000, 2),
                score=round(score, 3),
                event_age_s=round(time.monotonic() - event_time, 2),
            )
            self.cv.notify_all()

    def _run(self):
        while not self.stop_event.is_set():
            selected = None

            with self.cv:
                now = time.monotonic()
                offset = self.offset if self.enabled else 0.0
                delays = {CHANNEL_LEFT: max(0.0, offset), CHANNEL_RIGHT: max(0.0, -offset)}
                due = []

                for ch, q in self.queues.items():
                    dropped = 0
                    oldest_age = now - q[0][0] if q else 0

                    while q and now - q[0][0] > 0.7:
                        q.popleft()
                        dropped += 1

                    if dropped:
                        self._record_drops(
                            ch, dropped, "sender", ["stale_frame"], oldest_age, offset
                        )

                    if q:
                        due.append((q[0][0] + delays[ch], ch))

                if due:
                    due_time, ch = min(due)

                    if due_time <= now:
                        _timestamp, jpeg = self.queues[ch].popleft()
                        frame_id = self.frame_ids[ch]
                        self.frame_ids[ch] = (frame_id + 1) & 0xFFFF
                        selected = (ch, frame_id, jpeg)
                    else:
                        self.cv.wait(timeout=min(0.025, max(0.001, due_time - now)))
                else:
                    self.cv.wait(timeout=0.025)

            if selected is None:
                continue

            ch, frame_id, jpeg = selected

            try:
                count = self.adapter.send(self.sock, self.target, ch, frame_id, jpeg)
                record_sent_frame(self.stats, self.stats_lock, ch, count, len(jpeg))
            except Exception as exc:
                record_send_error(self.stats, self.stats_lock, ch, frame_id, jpeg, exc)

                if not self.stop_event.is_set():
                    time.sleep(0.05)


def is_http_url(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def connection_error_message(exc):
    """연결·수신 중에 발생한 예외를 하단 상태 줄에 표시할 한국어 문구로 변환한다. 자세한 내용은 진단 로그에 그대로 남는다."""
    if type(exc) is ConnectionError:
        return str(exc)

    if isinstance(exc, urllib.error.HTTPError):
        return f"카메라가 HTTP {exc.code} 오류로 응답했습니다."

    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, Exception):
        exc = exc.reason

    if isinstance(exc, TimeoutError):
        return "카메라가 응답하지 않습니다(연결 시간 초과)."

    if isinstance(exc, socket.gaierror):
        return "카메라 주소를 찾을 수 없습니다. 주소와 네트워크를 확인하세요."

    if isinstance(exc, ConnectionRefusedError):
        return "카메라가 연결을 거부했습니다."

    # RemoteDisconnected는 ConnectionResetError이면서 HTTPException이기도 해서, 연결 끊김으로 먼저 분류한다.
    if isinstance(exc, ConnectionError):
        return "카메라 연결이 끊어졌습니다."

    if isinstance(exc, http.client.InvalidURL):
        return "카메라 주소 형식이 올바르지 않습니다."

    if isinstance(exc, http.client.HTTPException):
        return "카메라 응답이 올바르지 않습니다."

    if isinstance(exc, OSError):
        return "카메라와 통신하지 못했습니다."

    return f"연결 오류: {exc}"


class MJPEGWorker(threading.Thread):
    def __init__(
        self, name, url, channel, sock, target, stop_event, stats, stats_lock, synchronizer, adapter
    ):
        super().__init__(daemon=True, name=name)
        self.url, self.channel = url, channel
        self.sock, self.target = sock, target
        self.stop_event, self.stats, self.stats_lock = stop_event, stats, stats_lock
        self.synchronizer = synchronizer
        self.adapter = adapter
        self.frame_id = 0

    def set_stats(self, **kwargs):
        with self.stats_lock:
            s = self.stats[self.channel]

            for key, value in kwargs.items():
                setattr(s, key, value)

    @staticmethod
    def _close_quietly(response):
        if response is not None:
            try:
                response.close()
            except Exception:
                pass

    def run(self):
        uses_sync = self.synchronizer is not None and self.channel in EYE_CHANNELS
        retry_delay = 0.5
        attempts = 0
        worker_started = time.monotonic()
        last_complete_frame = worker_started
        last_data = worker_started

        while not self.stop_event.is_set():
            response = None
            buffer = bytearray()
            read_started = time.monotonic()
            attempts += 1
            diagnostic(
                "CONNECT_ATTEMPT",
                channel=self.channel,
                attempt=attempts,
                uptime_s=round(read_started - worker_started, 1),
            )

            try:
                req = urllib.request.Request(
                    self.url,
                    headers={
                        "User-Agent": "NareFace-PaperTracker-Bridge/1.1",
                        "Accept": "multipart/x-mixed-replace,image/jpeg,*/*",
                        "Connection": "close",
                    },
                )
                response = urllib.request.urlopen(req, timeout=READ_TIMEOUT)
                self.set_stats(connected=True, error="")
                diagnostic(
                    "CONNECTED",
                    channel=self.channel,
                    attempt=attempts,
                    connect_ms=round((time.monotonic() - read_started) * 1000, 1),
                    status=getattr(response, "status", None),
                )
                buffer = bytearray()
                last_complete_frame = time.monotonic()
                last_data = last_complete_frame

                # read(8192)는 8192바이트가 모일 때까지 기다릴 수 있다.
                # read1은 지금까지 도착한 만큼만 바로 돌려주므로 불필요하게 멈추지 않는다.
                read_chunk = getattr(response, "read1", response.read)

                while not self.stop_event.is_set():
                    try:
                        read_started = time.monotonic()
                        chunk = read_chunk(8192)
                    except TimeoutError as exc:
                        raise ConnectionError(
                            f"{READ_TIMEOUT:g}초 동안 스트림 데이터가 수신되지 않았습니다."
                        ) from exc

                    if not chunk:
                        raise ConnectionError("MJPEG 스트림 연결이 종료되었습니다.")

                    last_data = time.monotonic()
                    read_ms = (last_data - read_started) * 1000

                    if read_ms >= 200:
                        diagnostic(
                            "READ_SLOW",
                            logging.WARNING,
                            channel=self.channel,
                            read_ms=round(read_ms, 1),
                            bytes=len(chunk),
                        )

                    buffer.extend(chunk)

                    if len(buffer) > MAX_BUFFER_BYTES:
                        diagnostic(
                            "BUFFER_OVERFLOW",
                            logging.WARNING,
                            channel=self.channel,
                            buffered_bytes=len(buffer),
                        )
                        last_soi = buffer.rfind(b"\xff\xd8")

                        if last_soi >= 0:
                            del buffer[:last_soi]
                        else:
                            buffer.clear()

                    while True:
                        start = buffer.find(b"\xff\xd8")

                        if start < 0:
                            # 마지막 바이트가 0xFF라면 다음 데이터와 합쳐져 JPEG 시작 표식(FF D8)이 될 수 있으므로
                            # 남겨 둔다.
                            if len(buffer) > 1:
                                del buffer[:-1]

                            break

                        end = buffer.find(b"\xff\xd9", start + 2)

                        if end < 0:
                            if start > 0:
                                del buffer[:start]

                            break

                        end += 2
                        jpeg = bytes(buffer[start:end])
                        del buffer[:end]
                        arrived = time.monotonic()
                        gap = arrived - last_complete_frame

                        if gap >= 0.2:
                            diagnostic(
                                "FRAME_GAP",
                                logging.WARNING,
                                channel=self.channel,
                                gap_ms=round(gap * 1000, 1),
                                jpeg_bytes=len(jpeg),
                                buffered_bytes=len(buffer),
                            )

                        last_complete_frame = arrived
                        retry_delay = 0.5

                        with self.stats_lock:
                            self.stats[self.channel].received += 1

                        if uses_sync:
                            self.synchronizer.add(self.channel, jpeg, arrived)

                            # 동기화 과정에서 프레임이 버려질 수 있으므로, 눈 채널의 상태는 전송 시각이 아닌
                            # 도착 시각으로 판단한다. 오류 표시는 전송 쪽에서 관리하고, 다시 연결되면 그때 지운다.
                            self.set_stats(connected=True, last_frame_time=arrived)
                        else:
                            frame_id = self.frame_id
                            self.frame_id = (frame_id + 1) & 0xFFFF

                            # 패킷 코드, 카메라 회전·반전, UDP 전송에서 오류가 나도 문제없는 카메라 연결까지 끊지는 않는다.
                            try:
                                count = self.adapter.send(
                                    self.sock, self.target, self.channel, frame_id, jpeg
                                )
                            except Exception as exc:
                                record_send_error(
                                    self.stats, self.stats_lock, self.channel, frame_id, jpeg, exc
                                )
                                continue

                            record_sent_frame(
                                self.stats, self.stats_lock, self.channel, count, len(jpeg), arrived
                            )

                    # 방금 받은 데이터를 먼저 처리한 다음, 스트림이 멈췄는지 확인한다.
                    if time.monotonic() - last_complete_frame > READ_TIMEOUT:
                        raise ConnectionError(
                            f"{READ_TIMEOUT:g}초 동안 완전한 JPEG 프레임이 수신되지 않았습니다."
                        )
            except Exception as exc:
                if self.stop_event.is_set():
                    break

                # IncompleteRead, BadStatusLine 같은 http.client 오류는 OSError가 아니어서 따로 지정한다.
                # InvalidURL도 여기에 속하지만, 주소 형식이 틀린 경우라 다시 시도해도 소용없다.
                retry = isinstance(exc, (OSError, http.client.HTTPException)) and not isinstance(
                    exc, http.client.InvalidURL
                )
                failure_time = time.monotonic()

                with self.stats_lock:
                    state = dict(vars(self.stats[self.channel]))

                diagnostic(
                    "DISCONNECTED",
                    logging.WARNING,
                    channel=self.channel,
                    attempt=attempts,
                    uptime_s=round(failure_time - worker_started, 1),
                    error_type=type(exc).__name__,
                    error=str(exc),
                    cause=repr(exc.__cause__),
                    errno=getattr(exc, "errno", None),
                    winerror=getattr(exc, "winerror", None),
                    data_gap_s=round(failure_time - last_data, 3),
                    frame_gap_s=round(failure_time - last_complete_frame, 3),
                    read_ms=round((failure_time - read_started) * 1000, 1),
                    buffered_bytes=len(buffer),
                    stats=state,
                    retry=retry,
                    retry_delay_s=retry_delay,
                )
                self.set_stats(connected=False, error=connection_error_message(exc))

                if uses_sync:
                    self.synchronizer.reset_channel(self.channel)

                if not retry:
                    break

                # 기다리기 전에 연결부터 닫는다. 다시 연결하는 것은 실패한 이 채널뿐이다.
                self._close_quietly(response)
                response = None
                diagnostic(
                    "RECONNECT_WAIT",
                    channel=self.channel,
                    delay_s=retry_delay,
                    next_attempt=attempts + 1,
                )

                if self.stop_event.wait(retry_delay):
                    break

                retry_delay = min(5.0, retry_delay * 2)
            finally:
                self._close_quietly(response)

        diagnostic(
            "STREAM_STOPPED",
            channel=self.channel,
            uptime_s=round(time.monotonic() - worker_started, 1),
            requested=self.stop_event.is_set(),
        )


class HealthMonitor:
    """채널별 수신·전송 FPS를 구간마다 계산하고, 크게 떨어지거나 회복되면 진단 로그를 남긴다."""

    def __init__(self):
        self.reset()

    def reset(self):
        self._previous = {}
        self._baseline = {}
        self._degraded = set()

    def update(self, snapshot, elapsed):
        rates = {}

        for channel, state in snapshot.items():
            previous = self._previous.get(channel, (0, 0))
            rates[channel] = {
                "rx": round((state.received - previous[0]) / elapsed, 2),
                "tx": round((state.frames - previous[1]) / elapsed, 2),
            }
            self._previous[channel] = (state.received, state.frames)

            for direction, fps in rates[channel].items():
                key = (channel, direction)

                # 기준 FPS는 정상일 때만 지수 평균으로 갱신한다.
                # 기준의 70% 밑으로 떨어지면 경고를 한 번 남기고, 85% 이상으로 회복되면 경고 상태를 푼다.
                baseline = self._baseline.get(key, fps)

                if baseline >= 5 and fps < baseline * 0.7:
                    if key not in self._degraded:
                        diagnostic(
                            "FPS_DROP",
                            logging.WARNING,
                            channel=channel,
                            direction=direction,
                            fps=fps,
                            baseline_fps=round(baseline, 2),
                            window_s=round(elapsed, 2),
                            connected=state.connected,
                            error=state.error,
                        )
                        self._degraded.add(key)
                elif key in self._degraded:
                    if fps >= baseline * 0.85:
                        diagnostic(
                            "FPS_RECOVERED",
                            channel=channel,
                            direction=direction,
                            fps=fps,
                            baseline_fps=round(baseline, 2),
                        )
                        self._degraded.discard(key)
                else:
                    self._baseline[key] = baseline * 0.8 + fps * 0.2

        return rates


@dataclass(frozen=True)
class StreamInfo:
    name: str
    label: str
    icon: str
    channel: int
    default_url: str


class BridgeApp:
    STREAMS = (
        StreamInfo("Face", "얼굴", "◎", CHANNEL_FACE, "http://nareface.local/face"),
        StreamInfo("Left eye", "왼쪽 눈", "◉", CHANNEL_LEFT, "http://nareface.local/left"),
        StreamInfo("Right eye", "오른쪽 눈", "◉", CHANNEL_RIGHT, "http://nareface.local/right"),
    )

    def __init__(self, root):
        self.root = root
        self._apply_window_icon(root)
        self.root.title(f"나래 - 외부 Facial 브릿지 v{APP_VERSION} by 백설기@")
        self.root.geometry("1280x900")
        self.root.minsize(1180, 1)
        self.root.resizable(True, False)
        self.sock = None
        self.stop_event = None
        self._reconnect_pending = False
        self._stop_timer = None

        # 대상 주소를 찾는 동안에는 확인 타이머 ID를 담고, 그 밖에는 None이다.
        self._resolve_timer = None
        self.workers = []
        self.synchronizer = None
        self.adapter = None
        self.adapter_code = ""
        self._last_ui_error = ""
        self._auto_start_timer = None

        # ‘연결 시작’이나 ‘정지’를 누른 뒤에는, 대상 IP·포트·카메라 주소를 바꾸거나 패킷 코드를 저장하기 전까지 자동으로 연결하지 않는다.
        self._auto_start_suspended = False
        self._editor_draft = None
        self.adapter_path = APP_DIRECTORY / "packet_adapter.json"
        self.settings = SettingsStore(APP_DIRECTORY / "settings.json")
        port = self.settings.get("port")
        self._saved_port = port if type(port) is int and 1 <= port <= 65535 else None
        self._port_save_timer = None
        self._url_save_timer = None
        self._target_ip_save_timer = None
        programs = self.settings.get("programs", [])
        self.program_window = None
        self.program_list = None
        self.companion_programs = (
            [path for path in programs if isinstance(path, str) and path.strip()]
            if isinstance(programs, list)
            else []
        )
        self.editor_window = None
        self._editor_widget = None
        self._close_editor = None
        self._sync_panel_timer = None
        self._startup_error = None

        if self.adapter_path.exists():
            try:
                self.adapter_code = read_adapter_file(self.adapter_path)
            except Exception as exc:
                self._startup_error = self._error_message(exc)

        self.stats_lock = threading.Lock()
        self._reset_stats()
        self.rx_fps_vars, self.drop_vars = {}, {}
        self.health = HealthMonitor()
        self._session_start = time.monotonic()
        self._log_time = time.monotonic()
        self.prev_time = time.monotonic()
        self.frame_transforms = FrameTransforms(self.settings.get("camera_transforms"))
        self.rotation_vars, self.mirror_buttons = {}, {}
        self.url_vars, self.status_vars = {}, {}
        self.tx_fps_vars, self.size_vars = {}, {}
        self.sync_var = tk.BooleanVar(
            master=self.root, value=self.settings.get("eye_sync", True) is not False
        )
        self._build_ui()
        self.root.after(100, self._center_main_window)
        self.root.after(500, self._launch_companion_programs)

        for variable in (self.target_port_var, self.target_ip_var, *self.url_vars.values()):
            variable.trace_add("write", self._connection_settings_changed)

        self.target_port_var.trace_add("write", self._schedule_port_save)
        self.target_ip_var.trace_add("write", self._schedule_target_ip_save)

        for variable in self.url_vars.values():
            variable.trace_add("write", self._schedule_url_save)

        if self._startup_error:
            self.root.after(
                0,
                lambda: self._show_error(
                    "자동 불러오기 실패", self._startup_error, parent=self.root
                ),
            )
        elif self.adapter_path.exists():
            self.adapter_status_var.set("저장된 JSON 자동 불러오기 완료")

        self.root.after(500, self._update_ui)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _reset_stats(self):
        with self.stats_lock:
            self.stats = {ch: StreamStats() for ch in CHANNELS}
            _SEND_ERROR_LOG.clear()
            self.prev_sent = dict.fromkeys(CHANNELS, 0)
            self.prev_received = dict.fromkeys(CHANNELS, 0)

    def save_adapter_json(self, code):
        write_adapter_file(self.adapter_path, code)
        self.adapter_code = code
        self._editor_draft = None
        self._auto_start_suspended = False
        self.adapter_status_var.set("JSON 저장 완료 · 다음 실행 시 자동 불러오기")
        self._refresh_readiness()

    def _build_ui(self):
        self.root.configure(bg=BG)
        style = ttk.Style(self.root)
        style.theme_use("clam")

        if "FlatEntry.field" not in style.element_names():
            style.element_create("FlatEntry.field", "from", "default", "Entry.field")

        style.layout(
            "TEntry",
            [
                (
                    "FlatEntry.field",
                    {
                        "sticky": "nswe",
                        "children": [
                            (
                                "Entry.padding",
                                {
                                    "sticky": "nswe",
                                    "children": [("Entry.textarea", {"sticky": "nswe"})],
                                },
                            )
                        ],
                    },
                )
            ],
        )
        style.layout(
            "TButton",
            [
                (
                    "Button.border",
                    {
                        "sticky": "nswe",
                        "children": [
                            (
                                "Button.padding",
                                {
                                    "sticky": "nswe",
                                    "children": [("Button.label", {"sticky": "nswe"})],
                                },
                            )
                        ],
                    },
                )
            ],
        )
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=WHITE, font=(FONT, 10))
        style.configure("Title.TLabel", font=(FONT, 24, "bold"), foreground=WHITE)
        style.configure("Muted.TLabel", foreground=MUTED, font=(FONT, 9))
        style.configure(
            "TButton",
            font=(FONT, 10),
            padding=(14, 10),
            background=CONTROL_BG,
            foreground=WHITE,
            borderwidth=0,
        )
        style.map(
            "TButton",
            background=[("active", "#30435a"), ("disabled", "#182332")],
            foreground=[("disabled", "#65768c")],
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#321819",
            font=(FONT, 11, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("disabled", "#412b32"), ("active", "#ffa5a7")],
            foreground=[("disabled", "#9b7077")],
        )
        style.configure(
            "TEntry",
            padding=7,
            fieldbackground=FIELD_BG,
            foreground=WHITE,
            insertcolor=WHITE,
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            bordercolor=FIELD_BG,
            lightcolor=FIELD_BG,
            darkcolor=FIELD_BG,
        )
        style.map(
            "TEntry", fieldbackground=[("focus", FIELD_ACTIVE)], bordercolor=[("focus", ACCENT)]
        )
        style.configure("TCheckbutton", background=PANEL, foreground=WHITE, font=(FONT, 10))
        style.map("TCheckbutton", background=[("active", PANEL)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(16, 10))
        style.map(
            "TNotebook.Tab", background=[("selected", "#25384a")], foreground=[("selected", ACCENT)]
        )

        def card(parent):
            return tk.Frame(
                parent, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=20, pady=12
            )

        outer = tk.Frame(self.root, bg=BG, padx=28, pady=14)
        outer.pack(fill="both", expand=True)
        self._main_content = outer
        self._fit_pending = None

        def schedule_fit(event=None):
            if self._fit_pending is None:
                self._fit_pending = self.root.after_idle(self._fit_main_window)

        outer.bind("<Configure>", schedule_fit)
        nav = tk.Frame(outer, bg=BG)
        nav.pack(fill="x", pady=(0, 12))
        nav.columnconfigure(1, weight=1)
        nav_labels = [
            self._label(nav, f"MJPEG / BRIDGE  v{APP_VERSION}", 13, bold=True),
            self._label(nav, "STREAM CONTROL STUDIO", 9, MUTED),
            self._label(nav, "●  로컬 처리", 10, ACCENT),
        ]
        descents = [
            tkfont.Font(root=self.root, font=item.cget("font")).metrics("descent")
            for item in nav_labels
        ]

        for column, (item, descent) in enumerate(zip(nav_labels, descents)):
            item.configure(pady=0, borderwidth=0)
            item.grid(
                row=0,
                column=column,
                sticky="sw" if column < 2 else "se",
                padx=(22, 0) if column == 1 else 0,
                pady=(0, max(descents) - descent),
            )

        hero = tk.Canvas(
            outer, height=294, bg="#0b1017", highlightthickness=1, highlightbackground=LINE
        )
        hero.pack(fill="x", pady=(0, 16))
        self._hero_original = None
        asset = asset_path("img.png")

        if asset is not None:
            try:
                if PIL_AVAILABLE:
                    with Image.open(asset) as banner:
                        self._hero_original = banner.convert("RGB")
                else:
                    self._hero_photo = tk.PhotoImage(file=str(asset))
            except (OSError, ValueError, tk.TclError):
                self._hero_original = None

        def draw_hero(event=None):
            width = max(hero.winfo_width(), 1)
            height = max(1, round(width * 300 / 1500))

            if int(hero.cget("height")) != height:
                hero.configure(height=height)
                schedule_fit()

            hero.delete("all")

            if self._hero_original is not None:
                image = self._hero_original
                scale = max(width / image.width, height / image.height)
                resized = image.resize(
                    (math.ceil(image.width * scale), math.ceil(image.height * scale)),
                    Image.Resampling.LANCZOS,
                )

                # 캔버스 비율은 5:1이다. 높이가 남으면 위에서 22% 되는 지점부터, 너비가 남으면 가운데를
                # 잘라서 보여 준다.
                left = (resized.width - width) // 2
                top = max(0, int((resized.height - height) * 0.22))
                self._hero_photo = ImageTk.PhotoImage(
                    resized.crop((left, top, left + width, top + height))
                )
                hero.create_image(0, 0, image=self._hero_photo, anchor="nw")
            elif hasattr(self, "_hero_photo"):
                hero.create_image(width, height // 2, image=self._hero_photo, anchor="e")

            hero.create_text(
                26,
                18,
                anchor="nw",
                text="CAPTURE. SYNC. SEND. [by '백설기@']",
                fill=ACCENT,
                font=(LATIN_FONT, 10, "bold"),
            )
            hero.create_text(
                24,
                43,
                anchor="nw",
                text="나래 - 외부 Facial 브릿지",
                fill=WHITE,
                font=(FONT, 26, "bold"),
            )
            hero.create_text(
                26,
                91,
                anchor="nw",
                text="브붕이들아 언제든 행복해야해~!!",
                fill="#afbfce",
                font=(FONT, 10),
            )
            hero.create_text(
                26,
                120,
                anchor="nw",
                text="JPEG ORIGINAL    /    EYE SYNC    /    CUSTOM PACKETS",
                fill="#7b91a5",
                font=(LATIN_FONT, 9),
            )

        hero.bind("<Configure>", draw_hero)

        body = tk.Frame(outer, bg=BG)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)
        streams = card(body)
        streams.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        heading = tk.Frame(streams, bg=PANEL)
        heading.pack(fill="x", pady=(0, 12))
        self._label(heading, "스트림 모니터", 15, bold=True).pack(side="left")
        self._label(heading, "3 CHANNELS", 9, MUTED).pack(side="right")
        self.status_labels = {}
        small_button = {
            "activebackground": FIELD_ACTIVE,
            "activeforeground": WHITE,
            "relief": "flat",
            "borderwidth": 0,
            "highlightthickness": 0,
            "takefocus": False,
            "font": (FONT, 9),
            "padx": 7,
            "pady": 2,
        }

        for stream in self.STREAMS:
            ch = stream.channel
            row = tk.Frame(
                streams, bg=INSET, highlightbackground=LINE, highlightthickness=1, padx=14, pady=4
            )
            row.pack(fill="x", pady=(0, 10))
            top = tk.Frame(row, bg=INSET)
            top.pack(fill="x", pady=(0, 6))
            self._label(top, stream.icon, 17, ACCENT).pack(side="left", padx=(0, 9))
            self._label(top, stream.label, 12, bold=True).pack(side="left")
            self._label(top, f"CH 0{ch + 1}", 9, MUTED).pack(side="left", padx=(12, 8))
            rotation, mirror = self.frame_transforms.get(ch)
            self.rotation_vars[ch] = tk.StringVar(value=f"↻ {rotation}°")
            rotation_button = tk.Button(
                top,
                textvariable=self.rotation_vars[ch],
                command=lambda channel=ch: self._change_camera_transform(channel, rotate=True),
                bg=FIELD_BG,
                fg=ACCENT,
                **small_button,
            )
            rotation_button.pack(side="left", padx=(0, 5))
            mirror_button = tk.Button(
                top,
                text="↔ 반전",
                command=lambda channel=ch: self._change_camera_transform(channel, mirror=True),
                **small_button,
            )
            self._style_mirror_button(mirror_button, mirror)
            mirror_button.pack(side="left")
            self.mirror_buttons[ch] = mirror_button

            if not PIL_AVAILABLE:
                rotation_button.configure(state="disabled")
                mirror_button.configure(state="disabled")

            self.status_vars[ch] = tk.StringVar(value="대기")
            status = self._label(top, size=9, color=MUTED, textvariable=self.status_vars[ch])
            status.pack(side="right")
            self.status_labels[ch] = status
            saved_urls = self.settings.get("stream_urls", {})
            saved_url = (
                saved_urls.get(str(ch), stream.default_url)
                if isinstance(saved_urls, dict)
                else stream.default_url
            )
            self.url_vars[ch] = tk.StringVar(
                value=saved_url if isinstance(saved_url, str) else stream.default_url
            )
            ttk.Entry(row, textvariable=self.url_vars[ch]).pack(fill="x")
            metrics = tk.Frame(row, bg=INSET)
            metrics.pack(fill="x", pady=(6, 0))
            self.tx_fps_vars[ch] = tk.StringVar(value="0.0")
            self.size_vars[ch] = tk.StringVar(value="—")
            self.rx_fps_vars[ch] = tk.StringVar(value="0.0")
            self.drop_vars[ch] = tk.StringVar(value="0")

            for title, var in [
                ("수신 FPS", self.rx_fps_vars[ch]),
                ("전송 FPS", self.tx_fps_vars[ch]),
                ("DROP", self.drop_vars[ch]),
                ("JPEG", self.size_vars[ch]),
            ]:
                self._label(metrics, title, 8, MUTED).pack(side="left", padx=(0, 7))
                self._label(metrics, size=10, textvariable=var).pack(side="left", padx=(0, 22))

        self._build_sync_panel(streams)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        packet = card(right)
        packet.pack(fill="x", pady=(0, 14))
        packet_header = tk.Frame(packet, bg=PANEL)
        packet_header.pack(fill="x")
        self._label(packet_header, "{ / }", 18, ACCENT, True).pack(side="left")
        self._label(packet_header, "PACKET WORKSPACE", 9, MUTED).pack(side="right")
        self._label(packet, "사용자 지정 패킷", 17, bold=True).pack(anchor="w", pady=(8, 5))
        self._label(packet, "Python 코드 편집과 JSON 저장", 10, MUTED).pack(anchor="w")
        packet_button = ttk.Button(
            packet,
            text="패킷 에디터 열기    ↗",
            style="Accent.TButton",
            command=self.open_packet_editor,
        )
        packet_button.pack(fill="x", ipady=11, pady=(16, 10))
        ttk.Button(packet, text="↓  JSON 불러오기", command=self.load_adapter_json).pack(fill="x")
        self.adapter_status_var = tk.StringVar(value="저장하면 다음 실행 시 자동으로 불러옵니다.")
        self._label(
            packet,
            size=9,
            color=MUTED,
            textvariable=self.adapter_status_var,
            wraplength=390,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))

        target = card(right)
        target.pack(fill="x")
        self._label(target, "UDP 연결", 14, bold=True).pack(anchor="w", pady=(0, 10))
        fields = tk.Frame(target, bg=PANEL)
        fields.pack(fill="x")
        fields.columnconfigure(0, weight=3)
        fields.columnconfigure(1, weight=1)
        self._label(fields, "대상 IP", 9, MUTED).grid(row=0, column=0, sticky="w", pady=(0, 5))
        self._label(fields, "포트", 9, MUTED).grid(
            row=0, column=1, sticky="w", padx=(10, 0), pady=(0, 5)
        )
        saved_ip = self.settings.get("target_ip")
        self.target_ip_var = tk.StringVar(
            value=saved_ip if isinstance(saved_ip, str) and saved_ip.strip() else "127.0.0.1"
        )
        self.target_port_var = tk.StringVar(
            value=str(self._saved_port if self._saved_port is not None else DEFAULT_PORT)
        )
        ttk.Entry(fields, textvariable=self.target_ip_var, width=18).grid(
            row=1, column=0, sticky="ew"
        )
        ttk.Entry(fields, textvariable=self.target_port_var, width=7).grid(
            row=1, column=1, sticky="ew", padx=(10, 0)
        )
        actions = tk.Frame(target, bg=PANEL)
        actions.pack(fill="x", pady=(14, 0))
        self.start_btn = ttk.Button(
            actions, text="▶  연결 시작", style="Accent.TButton", command=self.start
        )
        self.start_btn.pack(side="left", fill="x", expand=True, padx=(0, 7))
        self.stop_btn = ttk.Button(
            actions, text="정지", command=self._stop_clicked, state="disabled"
        )
        self.stop_btn.pack(side="left", padx=(0, 7))
        self.reconnect_btn = ttk.Button(
            actions, text="재연결", command=self.reconnect, state="disabled"
        )
        self.reconnect_btn.pack(side="left")

        companions = card(right)
        companions.pack(side="bottom", fill="x", pady=(14, 0))
        self.program_count_var = tk.StringVar(
            value=f"함께 실행할 프로그램 {len(self.companion_programs)}개"
        )
        self._label(companions, textvariable=self.program_count_var, size=11).pack(side="left")
        ttk.Button(companions, text="프로그램 관리", command=self.open_program_manager).pack(
            side="right"
        )

        footer = tk.Frame(outer, bg=BG)
        footer.pack(fill="x", pady=(10, 0))
        self.main_status_var = tk.StringVar()
        self.ready_indicator = self._label(footer, "●", 10, ERROR_RED)
        self.ready_indicator.pack(side="left", padx=(0, 8))
        self._label(
            footer,
            size=9,
            color=MUTED,
            textvariable=self.main_status_var,
            wraplength=1030,
            justify="left",
        ).pack(side="left")
        self._label(footer, "UDP / MJPEG", 9, MUTED).pack(side="right")
        self._refresh_readiness()

    @staticmethod
    def _label(parent, text=None, size=10, color=WHITE, bold=False, **kw):
        # 부모의 배경색을 그대로 받아 오므로 tk 위젯 안에서만 사용한다(ttk 위젯에는 bg가 없다).
        return tk.Label(
            parent,
            text=text,
            bg=parent.cget("bg"),
            fg=color,
            font=(FONT, size, "bold" if bold else "normal"),
            **kw,
        )

    def _apply_window_icon(self, window):
        window.after_idle(lambda: self._theme_title_bar(window))
        png, ico = asset_path("app_icon.png"), asset_path("app_icon.ico")

        try:
            if not hasattr(self, "_app_icon") and png is not None:
                self._app_icon = tk.PhotoImage(master=self.root, file=str(png))

            if hasattr(self, "_app_icon"):
                window.iconphoto(True, self._app_icon)

            if os.name == "nt" and ico is not None:
                window.iconbitmap(str(ico))
        except tk.TclError:
            pass

    @staticmethod
    def _theme_title_bar(window):
        if os.name != "nt" or not window.winfo_exists():
            return

        try:
            hwnd = BridgeApp._window_handle(window)
            set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            set_attribute.argtypes = [
                wintypes.HWND,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_attribute.restype = ctypes.c_long
            dark = wintypes.BOOL(1)

            # 20은 다크 모드 속성이다. 실패하면 예전 Windows 10에서 사용하던 19로 다시 시도한다.
            if set_attribute(hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark)) != 0:
                set_attribute(hwnd, 19, ctypes.byref(dark), ctypes.sizeof(dark))

            # Windows 11의 제목 표시줄, 제목 글자, 창 테두리 색이다(COLORREF, 0x00BBGGRR).
            for attribute, color in [(35, 0x0019110C), (36, 0x00FAF4EE), (34, 0x00443326)]:
                value = wintypes.DWORD(color)
                set_attribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value))
        except (AttributeError, OSError, tk.TclError):
            pass

    @staticmethod
    def _window_handle(window):
        user = ctypes.windll.user32
        user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user.GetAncestor.restype = wintypes.HWND
        return user.GetAncestor(window.winfo_id(), 2)  # 2는 GA_ROOT(최상위 창)

    def _change_camera_transform(self, channel, rotate=False, mirror=False):
        rotation, flipped = self.frame_transforms.get(channel)

        if rotate:
            rotation = (rotation + 90) % 360

        if mirror:
            flipped = not flipped

        settings = self.frame_transforms.to_settings()
        settings[str(channel)] = {"rotation": rotation, "mirror": flipped}

        if not self._save_settings(camera_transforms=settings):
            return

        self.frame_transforms.set(channel, rotation, flipped)
        self.rotation_vars[channel].set(f"↻ {rotation}°")
        self._style_mirror_button(self.mirror_buttons[channel], flipped)
        diagnostic("CAMERA_TRANSFORM", channel=channel, rotation=rotation, mirror=flipped)

    @staticmethod
    def _style_mirror_button(button, mirrored):
        button.configure(bg=ACCENT if mirrored else FIELD_BG, fg=BG if mirrored else WHITE)

    def _reschedule(self, timer, callback):
        if timer is not None:
            self.root.after_cancel(timer)

        return self.root.after(500, callback)

    def _schedule_url_save(self, *args):
        self._url_save_timer = self._reschedule(self._url_save_timer, self._save_stream_urls)

    def _save_stream_urls(self):
        self._url_save_timer = None
        urls = {str(ch): variable.get() for ch, variable in self.url_vars.items()}

        if self.settings.get("stream_urls") != urls:
            self._save_settings(stream_urls=urls)

    def _schedule_target_ip_save(self, *args):
        self._target_ip_save_timer = self._reschedule(
            self._target_ip_save_timer, self._save_target_ip
        )

    def _save_target_ip(self):
        self._target_ip_save_timer = None
        target_ip = self.target_ip_var.get().strip()

        if target_ip and self.settings.get("target_ip") != target_ip:
            self._save_settings(target_ip=target_ip)

    def _schedule_port_save(self, *args):
        self._port_save_timer = self._reschedule(self._port_save_timer, self._save_port)

    def _save_port(self):
        self._port_save_timer = None
        port = self._parse_port()

        if port is None or port == self._saved_port:
            return

        if self._save_settings(port=port):
            self._saved_port = port

    def _flush_pending_saves(self):
        for timer in (self._port_save_timer, self._url_save_timer, self._target_ip_save_timer):
            if timer is not None:
                self.root.after_cancel(timer)

        self._save_port()
        self._save_stream_urls()
        self._save_target_ip()

    def _parse_port(self):
        try:
            port = int(self.target_port_var.get().strip())
        except ValueError:
            return None

        return port if 1 <= port <= 65535 else None

    def _save_settings(self, **changes):
        try:
            self.settings.save(**changes)
        except OSError as exc:
            self._show_error("설정 저장 실패", self._error_message(exc), parent=self.root)
            return False

        return True

    def open_program_manager(self):
        if self.program_window is not None and self.program_window.winfo_exists():
            self.program_window.lift()
            self.program_window.focus_set()
            return

        win = tk.Toplevel(self.root)
        self._apply_window_icon(win)
        self.program_window = win
        win.title("함께 실행할 프로그램 관리")
        win.geometry("780x420")
        win.minsize(640, 340)
        win.transient(self.root)
        win.configure(bg=BG)
        outer = ttk.Frame(win, padding=22)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)
        ttk.Label(outer, text="함께 실행할 프로그램", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            outer, text="등록한 프로그램은 앱을 켤 때 한 번씩 실행됩니다.", style="Muted.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=(4, 14))
        style = ttk.Style(self.root)
        style.configure(
            "Programs.Treeview",
            background=INSET,
            fieldbackground=INSET,
            foreground=WHITE,
            rowheight=32,
            borderwidth=0,
            font=(FONT, 10),
        )
        style.map(
            "Programs.Treeview",
            background=[("selected", "#3d2933")],
            foreground=[("selected", ACCENT)],
        )
        style.configure(
            "Programs.Treeview.Heading", background=CONTROL_BG, foreground=WHITE, padding=8
        )
        area = ttk.Frame(outer)
        area.grid(row=2, column=0, sticky="nsew")
        self.program_list = ttk.Treeview(
            area,
            columns=("name", "path"),
            show="headings",
            height=5,
            selectmode="browse",
            style="Programs.Treeview",
        )
        self.program_list.heading("name", text="프로그램")
        self.program_list.heading("path", text="실행 파일 경로")
        self.program_list.column("name", width=160, minwidth=100)
        self.program_list.column("path", width=510, minwidth=200)
        self.program_list.grid(row=0, column=0, sticky="nsew")
        area.rowconfigure(0, weight=1)
        area.columnconfigure(0, weight=1)
        actions = ttk.Frame(outer)
        actions.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        ttk.Button(
            actions,
            text="프로그램 등록",
            style="Accent.TButton",
            command=self._add_companion_program,
        ).pack(side="left")
        self.remove_program_btn = ttk.Button(
            actions, text="선택 제거", command=self._remove_companion_program, state="disabled"
        )
        self.remove_program_btn.pack(side="left", padx=8)
        ttk.Button(actions, text="닫기", command=self._close_program_manager).pack(side="right")
        self.program_list.bind(
            "<<TreeviewSelect>>",
            lambda event: self.remove_program_btn.configure(
                state="normal" if self.program_list.selection() else "disabled"
            ),
        )
        self.program_list.bind("<Delete>", lambda event: self._remove_companion_program())
        win.protocol("WM_DELETE_WINDOW", self._close_program_manager)
        self._refresh_program_list()

    def _close_program_manager(self):
        if self.program_window is not None:
            self.program_window.destroy()
            self.program_window = None
            self.program_list = None

    def _refresh_program_list(self):
        self.program_count_var.set(f"함께 실행할 프로그램 {len(self.companion_programs)}개")

        if self.program_list is None or not self.program_list.winfo_exists():
            return

        self.program_list.delete(*self.program_list.get_children())

        for index, path in enumerate(self.companion_programs):
            self.program_list.insert("", "end", iid=str(index), values=(Path(path).name, path))

        self.remove_program_btn.configure(state="disabled")

    def _add_companion_program(self):
        path = filedialog.askopenfilename(
            parent=self.program_window or self.root,
            title="함께 실행할 프로그램 선택",
            filetypes=[("실행 프로그램", "*.exe")],
        )

        if not path:
            return

        path = str(Path(path).resolve())

        if Path(path).suffix.lower() != ".exe" or not Path(path).is_file():
            self._show_error("프로그램을 확인하세요", "실행할 수 있는 .exe 파일을 선택하세요.")
            return

        if any(
            os.path.normcase(item) == os.path.normcase(path) for item in self.companion_programs
        ):
            self._show_info("이미 등록된 프로그램", "이 프로그램은 이미 목록에 있습니다.")
            return

        programs = self.companion_programs + [path]

        if self._save_settings(programs=programs):
            self.companion_programs = programs
            self._refresh_program_list()

    def _remove_companion_program(self):
        selected = self.program_list.selection()

        if not selected:
            return

        programs = list(self.companion_programs)
        del programs[int(selected[0])]

        if self._save_settings(programs=programs):
            self.companion_programs = programs
            self._refresh_program_list()

    def _launch_companion_programs(self):
        errors = []

        for path in self.companion_programs:
            try:
                executable = Path(path)

                if executable.suffix.lower() != ".exe" or not executable.is_file():
                    raise FileNotFoundError(path)

                subprocess.Popen([str(executable)], cwd=str(executable.parent), shell=False)
            except (OSError, ValueError) as exc:
                errors.append(f"{Path(path).name}: {self._error_message(exc)}")

        if errors:
            self._show_error(
                "함께 실행할 프로그램 오류",
                "일부 프로그램을 실행하지 못했습니다.\n\n" + "\n".join(errors),
            )

    def _cancel_auto_start(self):
        if self._auto_start_timer is not None:
            self.root.after_cancel(self._auto_start_timer)
            self._auto_start_timer = None

    def _connection_settings_changed(self, *args):
        self._cancel_auto_start()
        self._auto_start_suspended = False
        self._refresh_readiness()

    def _readiness_error(self):
        if self._parse_port() is None:
            return "포트 번호를 1~65535 사이의 정수로 입력하세요."

        if not self.adapter_code.strip() or (
            self._editor_draft is not None and not self._editor_draft.strip()
        ):
            return "패킷 에디터에서 코드를 저장하거나 JSON을 불러오세요."

        if not self.target_ip_var.get().strip():
            return "UDP 대상 IP 주소를 입력하세요."

        if any(not var.get().strip() for var in self.url_vars.values()):
            return "모든 카메라 주소(URL)를 입력하세요."

        if any(not is_http_url(var.get().strip()) for var in self.url_vars.values()):
            return "카메라 주소는 http:// 또는 https://로 시작해야 합니다."

        return ""

    def _auto_start(self):
        self._auto_start_timer = None

        if not self.workers and not self._readiness_error() and not self._auto_start_suspended:
            self.start()

    def _refresh_readiness(self, draft=None):
        self._last_ui_error = ""

        if draft is not None:
            self._editor_draft = draft

        reason = self._readiness_error()
        ready = not reason

        with self.stats_lock:
            runtime_error = bool(self.workers) and any(stats.error for stats in self.stats.values())

        self.ready_indicator.configure(fg=ERROR_RED if runtime_error or not ready else READY_GREEN)

        if not ready:
            self._cancel_auto_start()

        if not self.workers and self._resolve_timer is None:
            self.start_btn.configure(state="normal" if ready else "disabled")

            if ready and not self._auto_start_suspended:
                if self._auto_start_timer is None:
                    self._auto_start_timer = self.root.after(3000, self._auto_start)

                self.main_status_var.set("준비 완료 · 3초 후 자동으로 연결을 시작합니다.")
            else:
                self.main_status_var.set(
                    "준비 완료 · 연결 시작을 눌러주세요." if ready else "준비 안 됨 · " + reason
                )

    @staticmethod
    def _error_message(exc):
        if isinstance(exc, json.JSONDecodeError):
            return f"JSON 파일 형식이 올바르지 않습니다.\n{exc.lineno}번째 줄, {exc.colno}번째 문자를 확인하세요."

        if isinstance(exc, SyntaxError):
            return f"Python 코드 문법이 올바르지 않습니다.\n{exc.lineno or 1}번째 줄을 확인하세요."

        if isinstance(exc, UnicodeError):
            return "파일을 읽을 수 없습니다. UTF-8 형식으로 저장한 파일을 선택하세요."

        if isinstance(exc, PermissionError):
            return "파일 접근 권한이 없습니다. 저장 위치와 파일 권한을 확인하세요."

        if isinstance(exc, FileNotFoundError):
            return "파일을 찾을 수 없습니다. 파일 경로를 확인하세요."

        if isinstance(exc, OSError):
            return "파일 또는 장치에 접근할 수 없습니다. 경로, 사용 권한, 연결 상태를 확인하세요."

        detail = str(exc)

        # 한글이 들어 있으면 사용자에게 보여 줄 문구로 판단해 그대로 사용한다.
        if any("가" <= char <= "힣" for char in detail):
            return detail

        return "처리 중 오류가 발생했습니다.\n오류 상세: " + detail

    def _show_error(self, title, message, parent=None):
        self._last_ui_error = title
        self.ready_indicator.configure(fg=ERROR_RED)
        self.main_status_var.set("오류 · " + title)
        return self._show_dialog(title, message, parent, error=True)

    def _show_info(self, title, message, parent=None):
        return self._show_dialog(title, message, parent, error=False)

    def _show_dialog(self, title, message, parent=None, error=True, buttons=(("확인", True),)):
        parent = parent or self.root
        result = None
        win = tk.Toplevel(parent)
        self._apply_window_icon(win)
        win.withdraw()
        win.title(title)
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(parent)
        content = tk.Frame(win, bg=BG, padx=26, pady=24)
        content.pack(fill="both", expand=True)
        badge = tk.Canvas(content, width=44, height=44, bg=BG, highlightthickness=0)
        badge.pack(anchor="w", pady=(0, 12))
        badge.create_oval(2, 2, 42, 42, fill="#332128", outline=ACCENT, width=1)
        badge.create_text(
            22, 22, text="!" if error else "i", fill=ACCENT, font=(LATIN_FONT, 21, "bold")
        )
        self._label(content, title, 16, bold=True, wraplength=420, justify="left").pack(anchor="w")
        self._label(content, message, color="#aebccd", wraplength=420, justify="left").pack(
            anchor="w", pady=(10, 22)
        )

        def choose(value):
            nonlocal result
            result = value
            win.destroy()

        row = tk.Frame(content, bg=BG)
        row.pack(anchor="e")

        for index, (text, value) in enumerate(buttons):
            ttk.Button(
                row,
                text=text,
                style="Accent.TButton" if index == 0 else "TButton",
                command=lambda value=value: choose(value),
            ).pack(side="left", ipadx=12, padx=(8 if index else 0, 0))

        button = row.winfo_children()[0]
        win.bind("<Return>", lambda event: choose(buttons[0][1]))
        win.bind("<Escape>", lambda event: win.destroy())
        win.update_idletasks()
        width = max(470, win.winfo_reqwidth())
        height = win.winfo_reqheight()
        x = max(0, parent.winfo_rootx() + (parent.winfo_width() - width) // 2)
        y = max(0, parent.winfo_rooty() + (parent.winfo_height() - height) // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")

        # 다른 모달 창이 이미 떠 있었다면, 이 대화상자를 닫은 뒤 그 창이 다시 입력을 독점(grab)하게 한다.
        previous = parent.grab_current()
        win.deiconify()
        win.grab_set()
        button.focus_set()
        parent.wait_window(win)

        if previous is not None and previous.winfo_exists():
            previous.grab_set()

        return result

    def _center_main_window(self):
        self._fit_main_window()
        self.root.update_idletasks()
        width, height = self.root.winfo_width(), self.root.winfo_height()
        left, top = 0, 0
        right, bottom = self.root.winfo_screenwidth(), self.root.winfo_screenheight()

        if os.name == "nt":

            class MonitorInfo(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("monitor", wintypes.RECT),
                    ("work", wintypes.RECT),
                    ("flags", wintypes.DWORD),
                ]

            user = ctypes.windll.user32
            user.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
            user.MonitorFromWindow.restype = wintypes.HANDLE
            user.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
            user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            hwnd = self._window_handle(self.root)
            info = MonitorInfo()
            info.size = ctypes.sizeof(info)

            if user.GetMonitorInfoW(user.MonitorFromWindow(hwnd, 2), ctypes.byref(info)):
                left, top, right, bottom = (
                    info.work.left,
                    info.work.top,
                    info.work.right,
                    info.work.bottom,
                )

            rect = wintypes.RECT()

            if user.GetWindowRect(hwnd, ctypes.byref(rect)):
                width, height = rect.right - rect.left, rect.bottom - rect.top

        x = left + max(0, (right - left - width) // 2)
        y = top + max(0, (bottom - top - height) // 2)
        self.root.geometry(f"+{x}+{y}")

    def _fit_main_window(self):
        self._fit_pending = None
        self.root.update_idletasks()
        width = max(1180, self.root.winfo_width())
        height = self._main_content.winfo_reqheight()

        if self.root.winfo_height() != height:
            self.root.geometry(f"{width}x{height}")

    def _build_sync_panel(self, parent):
        panel = tk.Frame(parent, bg=PANEL)
        panel.pack(fill="x", pady=(8, 0))
        tk.Frame(panel, bg=LINE, height=1).pack(fill="x", pady=(0, 12))
        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x", pady=(0, 10))
        box = tk.Canvas(
            row,
            width=28,
            height=28,
            bg=PANEL,
            highlightthickness=0,
            takefocus=True,
            cursor="hand2",
        )
        box.pack(side="left", padx=(0, 10))
        title = self._label(row, "눈 좌우 지연 동기화(매우 권장)", 12, bold=True, cursor="hand2")
        title.pack(side="left")

        def draw_box():
            box.delete("all")
            selected = self.sync_var.get()
            box.create_rectangle(
                3, 3, 25, 25, fill=INSET, outline=ACCENT if selected else "#73859a", width=2
            )

            if selected:
                box.create_rectangle(8, 8, 20, 20, fill=ACCENT, outline="")

            if box.focus_get() == box:
                box.create_rectangle(0, 0, 27, 27, outline=WHITE, dash=(2, 2))

        def toggle(event=None):
            self.sync_var.set(not self.sync_var.get())
            self._apply_eye_sync()
            draw_box()
            self._update_sync_panel()
            return "break"

        box.bind("<Button-1>", toggle)
        box.bind("<space>", toggle)
        box.bind("<Return>", toggle)
        box.bind("<FocusIn>", lambda event: draw_box())
        box.bind("<FocusOut>", lambda event: draw_box())
        title.bind("<Button-1>", toggle)
        draw_box()
        self.sync_value_vars = {key: tk.StringVar() for key in ("offset", "left", "right", "state")}
        self._label(row, size=9, color=MUTED, textvariable=self.sync_value_vars["state"]).pack(
            side="right"
        )
        metrics = tk.Frame(panel, bg=PANEL)
        metrics.pack(fill="x")

        for col, (key, title) in enumerate(
            [
                ("offset", "보정값 (오른쪽 − 왼쪽)"),
                ("left", "왼쪽 눈 지연"),
                ("right", "오른쪽 눈 지연"),
            ]
        ):
            metrics.columnconfigure(col, weight=1, uniform="sync")
            cell = tk.Frame(metrics, bg=INSET, padx=10, pady=8)
            cell.grid(row=0, column=col, sticky="ew", padx=(0, 8 if col < 2 else 0))
            self._label(cell, title, 9, MUTED).pack(anchor="w")
            self._label(
                cell, size=14, color=ACCENT, bold=True, textvariable=self.sync_value_vars[key]
            ).pack(anchor="w", pady=(3, 0))

        self._poll_sync_panel()

    def _apply_eye_sync(self):
        enabled = self.sync_var.get()
        self._save_settings(eye_sync=enabled)

        if self.synchronizer is not None:
            self.synchronizer.set_enabled(enabled)

            if not enabled and self.workers:
                # 분석이 밀리는 동안 쌓인 데이터를 버리기 위해 카메라 연결을 새로 연다.
                self.root.after_idle(self.reconnect)

    def _update_sync_panel(self):
        sync = self.synchronizer
        offset, confidence = 0.0, False

        if sync is not None:
            with sync.cv:
                offset = sync.offset if sync.enabled else 0.0
                confidence = sync.confidence

        if not self.sync_var.get():
            state = "동기화 꺼짐"
        elif sync is None:
            state = "연결 대기"
        elif not PIL_AVAILABLE:
            state = "Pillow 설치 필요"
        else:
            state = "보정 완료" if confidence else "눈 움직임 분석 중"

        self.sync_value_vars["offset"].set(f"{offset * 1000:+.1f} ms")
        self.sync_value_vars["left"].set(f"{max(0.0, offset) * 1000:.1f} ms")
        self.sync_value_vars["right"].set(f"{max(0.0, -offset) * 1000:.1f} ms")
        self.sync_value_vars["state"].set(state)

    def _poll_sync_panel(self):
        self._update_sync_panel()
        self._sync_panel_timer = self.root.after(200, self._poll_sync_panel)

    def _stop_sync_panel_polling(self):
        if self._sync_panel_timer is not None:
            self.root.after_cancel(self._sync_panel_timer)
            self._sync_panel_timer = None

    def load_adapter_json(self, parent=None, editor=None):
        parent = parent or self.root
        path = filedialog.askopenfilename(
            parent=parent,
            initialdir=self.adapter_path.parent,
            filetypes=[("패킷 JSON", "*.json")],
            title="패킷 JSON 불러오기",
        )

        if not path:
            return

        try:
            new_code = read_adapter_file(path)

            if editor is not None:
                editor.delete("1.0", "end")
                editor.insert("1.0", new_code)
            else:
                # 메인 창에서 불러온 JSON은 다음에 실행할 때도 사용하도록 기본 파일로 저장한다.
                previous_code = self.adapter_code
                self.save_adapter_json(new_code)
                self.adapter_status_var.set("JSON 불러오기 완료 · 기본 파일에 저장됨")

                if (
                    self._editor_widget is not None
                    and self._editor_widget.get("1.0", "end-1c") == previous_code
                ):
                    # 열려 있는 패킷 에디터가 저장된 코드를 그대로 보여 주고 있었다면 새 코드로 갱신한다.
                    # 편집 중이던 내용은 덮어쓰지 않는다. 이때는 패킷 에디터를 닫을 때 저장 여부를 묻는다.
                    self._editor_widget.delete("1.0", "end")
                    self._editor_widget.insert("1.0", new_code)
                    self._editor_widget.edit_modified(False)

                if self.workers:
                    self._show_info(
                        "불러오기 완료",
                        "새 코드는 재연결 또는 정지 후 시작하면 적용됩니다.",
                        parent=parent,
                    )
        except Exception as exc:
            self._show_error("JSON 불러오기 실패", self._error_message(exc), parent=parent)

    def open_packet_editor(self):
        if self.editor_window is not None and self.editor_window.winfo_exists():
            self.editor_window.lift()
            self.editor_window.focus_set()
            return

        win = tk.Toplevel(self.root)
        self._apply_window_icon(win)
        self.editor_window = win
        win.title("패킷 에디터")
        win.geometry("1000x760")
        win.minsize(900, 650)
        win.transient(self.root)
        win.configure(bg=BG)
        container = ttk.Frame(win, padding=22)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text="패킷 에디터", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            container,
            text="encode_frame(channel, frame_id, jpeg_bytes) → list[bytes]",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(3, 12))
        tabs = ttk.Notebook(container)
        tabs.pack(fill="both", expand=True)
        code_tab = ttk.Frame(tabs, padding=8)
        guide_tab = ttk.Frame(tabs, padding=8)
        tabs.add(code_tab, text="  Python 코드  ")
        tabs.add(guide_tab, text="  작성 가이드  ")
        code_tab.rowconfigure(0, weight=1)
        code_tab.columnconfigure(0, weight=1)
        code = tk.Text(
            code_tab,
            font=("Consolas", 12),
            wrap="none",
            undo=True,
            bg="#172033",
            fg="#e5eaf5",
            insertbackground="#ffffff",
            selectbackground="#3c4c75",
            padx=16,
            pady=14,
            relief="flat",
            borderwidth=0,
        )
        code.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(code_tab, orient="vertical", command=code.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(code_tab, orient="horizontal", command=code.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        code.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        code.insert("1.0", self.adapter_code)
        code.edit_modified(False)
        self._editor_widget = code

        def code_changed(event=None):
            if code.edit_modified():
                self._refresh_readiness(code.get("1.0", "end-1c"))
                code.edit_modified(False)

        code.bind("<<Modified>>", code_changed)

        def close_editor():
            if code.get("1.0", "end-1c") != self.adapter_code:
                choice = self._show_dialog(
                    "저장하지 않은 변경 사항",
                    "편집한 패킷 코드가 아직 저장되지 않았습니다.\n저장하지 않고 닫으면 변경 내용이 사라집니다.",
                    parent=win,
                    error=False,
                    buttons=(("저장", "save"), ("저장 안 함", "discard"), ("취소", None)),
                )

                if choice is None or (choice == "save" and not save_code()):
                    return False

            win.destroy()
            self._editor_widget = None
            self._editor_draft = None
            self._refresh_readiness()
            return True

        self._close_editor = close_editor
        win.protocol("WM_DELETE_WINDOW", close_editor)
        guide = tk.Text(
            guide_tab,
            font=("Consolas", 11),
            wrap="word",
            padx=14,
            pady=14,
            relief="flat",
            bg=PANEL,
            fg="#d5e2ee",
        )
        guide.pack(fill="both", expand=True)
        guide.insert("1.0", AI_GUIDE)
        guide.config(state="disabled")
        info = tk.StringVar(value="저장 위치: " + str(self.adapter_path))
        ttk.Label(container, textvariable=info, style="Muted.TLabel", wraplength=940).pack(
            anchor="w", pady=(12, 8)
        )

        def save_code():
            try:
                self.save_adapter_json(code.get("1.0", "end-1c"))
                info.set(
                    "JSON 저장 완료 · "
                    + (
                        "재연결하면 새 코드가 적용됩니다."
                        if self.workers
                        else "연결 시작 시 적용됩니다."
                    )
                )
                code.edit_modified(False)
                return True
            except Exception as exc:
                self._show_error("저장 실패", self._error_message(exc), parent=win)
                return False

        def copy_guide():
            self.root.clipboard_clear()
            self.root.clipboard_append(AI_GUIDE)
            info.set("AI 작성 가이드를 복사했습니다.")

        def export_code():
            path = filedialog.asksaveasfilename(
                parent=win, defaultextension=".py", filetypes=[("Python", "*.py")]
            )

            if path:
                try:
                    Path(path).write_text(code.get("1.0", "end-1c"), encoding="utf-8")
                    info.set("Python 파일 내보내기 완료")
                except OSError as exc:
                    self._show_error("내보내기 실패", self._error_message(exc), parent=win)

        def import_code():
            path = filedialog.askopenfilename(parent=win, filetypes=[("Python", "*.py")])

            if path:
                try:
                    new_code = Path(path).read_text(encoding="utf-8-sig")
                    validate_adapter_code(new_code)
                    code.delete("1.0", "end")
                    code.insert("1.0", new_code)
                    info.set("Python 코드 불러오기 완료 · 저장을 눌러 적용하세요.")
                except Exception as exc:
                    self._show_error("불러오기 실패", self._error_message(exc), parent=win)

        buttons = ttk.Frame(container)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="저장", style="Accent.TButton", command=save_code).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            buttons, text="JSON 불러오기", command=lambda: self.load_adapter_json(win, code)
        ).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text=".py 불러오기", command=import_code).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text=".py 내보내기", command=export_code).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="AI 가이드 복사", command=copy_guide).pack(side="left")
        ttk.Label(
            container,
            text="Ctrl+S로 JSON 저장 · 불러오기와 저장 시에는 코드가 실행되지 않습니다.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(6, 0))
        win.bind("<Control-s>", lambda event: (save_code(), "break")[1])

    def start(self):
        self._cancel_auto_start()
        self._auto_start_suspended = True

        if self.workers or self._resolve_timer is not None:
            return

        if not self.adapter_code.strip():
            self._refresh_readiness()
            self._show_error(
                "준비 안 됨",
                "패킷 에디터에서 코드를 저장하거나 JSON을 불러오세요.",
                parent=self.root,
            )
            return

        port = self._parse_port()

        if port is None:
            self._show_error(
                "포트 번호를 확인하세요", "포트 번호는 1~65535 사이의 정수로 입력하세요.\n예: 5000"
            )
            return

        target_ip = self.target_ip_var.get().strip()

        if not target_ip:
            self._show_error(
                "대상 주소를 확인하세요",
                "UDP 데이터를 받을 대상 IP 주소를 입력하세요.\n예: 127.0.0.1",
            )
            return

        urls = {ch: self.url_vars[ch].get().strip() for ch in CHANNELS}

        if any(not u for u in urls.values()):
            self._show_error(
                "카메라 주소를 확인하세요",
                "비어 있는 카메라 주소가 있습니다.\n얼굴, 왼쪽 눈, 오른쪽 눈의 MJPEG 주소(URL)를 모두 입력하세요.",
            )
            return

        if any(not is_http_url(u) for u in urls.values()):
            self._show_error(
                "카메라 주소를 확인하세요",
                "카메라 주소는 http:// 또는 https://로 시작해야 합니다.\n예: http://nareface.local/face",
            )
            return

        try:
            self.adapter = PacketAdapter(self.adapter_code, self.frame_transforms)

            # 연결을 시작하기 전에 작은 JPEG로 패킷 코드를 한 번 실행해 보고, 형식이 틀리면 바로 알린다.
            PacketAdapter.validate_packets(self.adapter.encode_frame(0, 0, b"\xff\xd8\xff\xd9"))
        except Exception as exc:
            self._show_error("패킷 코드를 확인하세요", self._error_message(exc))
            return

        self._resolve_target(target_ip, port, urls)

    def _resolve_target(self, target_ip, port, urls):
        # 호스트 이름은 여기서 한 번만 IP로 변환한다. sendto에 호스트 이름을 넘기면 프레임마다 주소를 다시 찾는다.
        # DNS 응답이 느리면 화면이 멈추므로 별도 스레드에서 찾고, 끝났는지는 after()로 확인한다.
        result = {}

        def resolve():
            try:
                result["ip"] = socket.gethostbyname(target_ip)
            except (OSError, UnicodeError):
                pass

        thread = threading.Thread(target=resolve, daemon=True, name="resolve-target")
        thread.start()

        def check_resolved():
            if thread.is_alive():
                self._resolve_timer = self.root.after(50, check_resolved)
                return

            self._resolve_timer = None

            if "ip" not in result:
                self.stop_btn.config(state="disabled")
                self._refresh_readiness()
                self._show_error(
                    "대상 주소를 확인하세요",
                    "UDP 대상 주소를 찾을 수 없습니다.\nIP 주소(예: 127.0.0.1)나 연결 가능한 호스트 이름을 입력하세요.",
                )
                return

            self._begin_session(target_ip, result["ip"], port, urls)

        self.start_btn.config(state="disabled")

        # DNS 응답이 오래 걸리면 ‘정지’로 취소할 수 있어야 한다.
        self.stop_btn.config(state="normal")
        self.main_status_var.set("대상 주소를 확인하는 중입니다.")
        self._resolve_timer = self.root.after(0, check_resolved)

    def _begin_session(self, target_ip, resolved_ip, port, urls):
        self.health.reset()
        self._session_start = time.monotonic()
        self._log_time = self._session_start
        diagnostic(
            "SESSION_START",
            target_ip=target_ip,
            resolved_ip=resolved_ip,
            port=port,
            sync_enabled=self.sync_var.get(),
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stop_event = threading.Event()
        self._last_ui_error = ""
        target = (resolved_ip, port)
        self._reset_stats()
        self.prev_time = time.monotonic()
        self.synchronizer = EyeSynchronizer(
            self.sock,
            target,
            self.stop_event,
            self.stats,
            self.stats_lock,
            self.adapter,
            enabled=self.sync_var.get(),
        )
        self.synchronizer.start()
        self.workers = []

        for stream in self.STREAMS:
            worker = MJPEGWorker(
                stream.name,
                urls[stream.channel],
                stream.channel,
                self.sock,
                target,
                self.stop_event,
                self.stats,
                self.stats_lock,
                self.synchronizer,
                self.adapter,
            )
            self.workers.append(worker)
            worker.start()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.reconnect_btn.config(state="normal")
        self.main_status_var.set(f"연결 시작 · {target_ip}:{port}")

    def reconnect(self):
        """기존 카메라 연결, 동기화 상태, UDP 소켓을 모두 정리한 뒤 새로 연결한다."""
        diagnostic("MANUAL_RECONNECT")

        if not self.workers:
            self.start()
            return

        self.main_status_var.set("모든 카메라 연결을 다시 시작하는 중입니다.")
        self.stop()

        # 이전 스레드가 아직 끝나지 않았으면, 같은 자원으로 연결을 하나 더 만들지 않고 기다린다.
        if self.workers:
            self.main_status_var.set("재연결 전에 기존 연결이 종료되기를 기다리는 중입니다.")
            self._reconnect_pending = True
            return

        self.start()

    def _stop_clicked(self):
        self._reconnect_pending = False
        self.stop()

    def stop(self):
        if self._resolve_timer is not None:
            # 대상 주소를 찾는 중에 정지하면 찾은 결과를 버린다.
            self.root.after_cancel(self._resolve_timer)
            self._resolve_timer = None

        # 확인 타이머가 두 개 돌면, 남은 타이머가 재연결로 새로 시작한 세션을 멈출 수 있다.
        if self._stop_timer is not None:
            self.root.after_cancel(self._stop_timer)
            self._stop_timer = None

        if self.workers and self.stop_event is not None and not self.stop_event.is_set():
            diagnostic("SESSION_STOP", uptime_s=round(time.monotonic() - self._session_start, 1))

        self._cancel_auto_start()
        self._auto_start_suspended = True

        if self.stop_event is not None:
            self.stop_event.set()

        # 여기서 join으로 기다리면 안 된다. 워커가 urlopen·read에서 최대 READ_TIMEOUT 동안
        # 머물 수 있어 그동안 화면이 멈춘다. 대신 after()로 스레드가 모두 끝났는지 주기적으로 확인한다.
        if self.synchronizer is not None:
            with self.synchronizer.cv:
                self.synchronizer.cv.notify_all()

        if any(worker.is_alive() for worker in self.workers) or (
            self.synchronizer is not None and self.synchronizer.is_alive()
        ):
            self.main_status_var.set("정지 중 · 카메라 연결이 종료되기를 기다립니다.")
            self._stop_timer = self.root.after(300, self.stop)
            return

        self.workers = []
        self.synchronizer = None

        if self.sock is not None:
            self.sock.close()
            self.sock = None

        self.stop_event = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.reconnect_btn.config(state="disabled")
        self._refresh_readiness()

        for ch in CHANNELS:
            self.status_vars[ch].set("대기")
            self.tx_fps_vars[ch].set("0.0")

        if self._reconnect_pending:
            self._reconnect_pending = False
            self.root.after(0, self.start)

    def _update_ui(self):
        now = time.monotonic()

        with self.stats_lock:
            snapshot = {ch: StreamStats(**vars(s)) for ch, s in self.stats.items()}

        self._update_stream_rows(snapshot, now)
        self._update_status_line(snapshot)

        if self.workers and now - self._log_time >= 5.0:
            self._log_health(snapshot, now)

        self.root.after(500, self._update_ui)

    def _update_stream_rows(self, snapshot, now):
        dt = max(now - self.prev_time, 0.001)

        for ch in CHANNELS:
            s = snapshot[ch]
            self.tx_fps_vars[ch].set(f"{(s.frames - self.prev_sent.get(ch, 0)) / dt:.1f}")
            self.rx_fps_vars[ch].set(f"{(s.received - self.prev_received.get(ch, 0)) / dt:.1f}")
            self.drop_vars[ch].set(str(s.dropped))
            self.size_vars[ch].set(
                f"{s.last_frame_size / 1024:.1f} KiB" if s.last_frame_size else "—"
            )
            self.prev_sent[ch] = s.frames
            self.prev_received[ch] = s.received
            status = self._stream_status(ch, s, now)
            self.status_vars[ch].set(status)

            if status == "● 전송 중":
                color = ACCENT
            elif s.error and self.workers:
                color = "#d14c60"
            else:
                color = MUTED

            self.status_labels[ch].configure(fg=color)

        self.prev_time = now

    def _stream_status(self, ch, s, now):
        if not self.workers:
            return "대기"

        if not s.connected:
            if not s.error:
                return "연결 중..."

            # 재시도하지 않는 오류가 난 워커는 이미 종료되어서 다시 연결되지 않는다.
            alive = any(w.channel == ch and w.is_alive() for w in self.workers)
            return "● 재연결 중" if alive else "● 연결 실패"

        if s.error:
            # 연결된 채널에 오류가 남아 있다면 전송 단계(패킷 코드, 카메라 회전·반전, UDP 전송)에서 실패한 것이다.
            # 어느 단계에서 실패했는지는 하단 상태 줄 문구로 알 수 있다.
            return "● 전송 오류"

        age = now - s.last_frame_time if s.last_frame_time else 999
        return "● 전송 중" if age < 2 else "응답 대기 중"

    def _update_status_line(self, snapshot):
        errors = [
            (stream.label, snapshot[stream.channel].error)
            for stream in self.STREAMS
            if self.workers and snapshot[stream.channel].error
        ]

        if errors or self._last_ui_error:
            self.ready_indicator.configure(fg=ERROR_RED)
            detail = " / ".join(f"{name}: {error[:55]}" for name, error in errors)
            self.main_status_var.set("오류 · " + (detail or self._last_ui_error))
            return

        if self.workers:
            self.ready_indicator.configure(fg=ERROR_RED if self._readiness_error() else READY_GREEN)

        stopping = self.stop_event is not None and self.stop_event.is_set()

        if self.synchronizer and not stopping:
            if not any(s.connected for s in snapshot.values()):
                self.main_status_var.set("연결 중 · 카메라 응답을 기다리는 중입니다.")
                return

            sync = self.synchronizer

            with sync.cv:
                enabled, confidence = sync.enabled, sync.confidence
                offset, dropped = sync.offset, sync.dropped

            if not enabled:
                eye = "눈 동기화 꺼짐"
            elif not PIL_AVAILABLE:
                eye = "눈 동기화 Pillow 설치 필요"
            else:
                state = "보정 완료" if confidence else "분석 중"
                eye = f"눈 동기화 보정값 {offset * 1000:+.0f} ms({state})"

            self.main_status_var.set(f"전송 중 · {eye} · 드롭 {dropped}개")

    def _log_health(self, snapshot, now):
        elapsed = now - self._log_time
        self._log_time = now
        rates = self.health.update(snapshot, elapsed)
        sync_state = {}

        if self.synchronizer is not None:
            with self.synchronizer.cv:
                sync = self.synchronizer
                sync_state = {
                    "enabled": sync.enabled,
                    "confidence": sync.confidence,
                    "offset_ms": round(sync.offset * 1000, 1),
                    "queued": {ch: len(q) for ch, q in sync.queues.items()},
                    "oldest_ms": {
                        ch: round((now - q[0][0]) * 1000, 1) if q else 0
                        for ch, q in sync.queues.items()
                    },
                    "analysis_ms": round(sync.analysis_ms, 2),
                    "calibration_ms": round(sync.calibration_ms, 2),
                }

        diagnostic(
            "HEALTH",
            uptime_s=round(now - self._session_start, 1),
            interval_s=round(elapsed, 2),
            log_records_lost=DIAGNOSTIC_HANDLER.lost if DIAGNOSTIC_HANDLER else 0,
            streams={
                ch: {
                    "rx": s.received,
                    "tx": s.frames,
                    "packets": s.packets,
                    "drop": s.dropped,
                    "rx_fps": self.rx_fps_vars[ch].get(),
                    "tx_fps": self.tx_fps_vars[ch].get(),
                    "gap_s": round(now - s.last_frame_time, 2) if s.last_frame_time else None,
                    "jpeg_bytes": s.last_frame_size,
                    "connected": s.connected,
                    "error": s.error,
                }
                for ch, s in snapshot.items()
            },
            window_fps=rates,
            sync=sync_state,
        )

    def _on_close(self):
        if (
            self.editor_window is not None
            and self.editor_window.winfo_exists()
            and not self._close_editor()
        ):
            return

        self._flush_pending_saves()
        self._cancel_auto_start()
        self._stop_sync_panel_polling()
        self._stop_clicked()
        threads = list(self.workers)

        if self.synchronizer is not None:
            threads.extend(self.synchronizer.threads())

        deadline = time.monotonic() + 1.0

        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

        # 스레드가 모두 끝났다면 UDP 소켓을 닫는 것까지 정리를 마친다.
        self.stop()
        self.root.destroy()


if __name__ == "__main__":
    configure_diagnostics()
    root = tk.Tk()
    BridgeApp(root)
    root.mainloop()
