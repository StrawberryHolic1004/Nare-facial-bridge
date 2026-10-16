import ast
import atexit
import io
import json
import logging
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
import urllib.request
from collections import deque
from dataclasses import dataclass
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from pathlib import Path
from tkinter import filedialog, ttk

# Optional dependency for visual eye-motion synchronization:
#   py -m pip install pillow
try:
    from PIL import Image, ImageChops, ImageStat, ImageTk

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
# Internal stream identifiers (not encoded into packets by the core).
CHANNEL_FACE, CHANNEL_LEFT, CHANNEL_RIGHT = 0, 1, 2
APP_VERSION = "1.0.7"
DEFAULT_PORT = 0000
READ_TIMEOUT = 3.0
MAX_BUFFER_BYTES = 16 * 1024 * 1024
MOTION_HISTORY_SECONDS = 4.0
LOGGER = logging.getLogger("narebridge")


class DiagnosticQueueHandler(QueueHandler):
    def __init__(self, log_queue):
        super().__init__(log_queue)
        self.lost = 0

    def enqueue(self, record):
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.lost += 1


class DiagnosticQueueListener(QueueListener):
    def enqueue_sentinel(self):
        self.queue.put(self._sentinel)


DIAGNOSTIC_LISTENER = None
DIAGNOSTIC_HANDLER = None


def configure_diagnostics():
    global DIAGNOSTIC_LISTENER, DIAGNOSTIC_HANDLER
    if DIAGNOSTIC_LISTENER is not None:
        return
    directory = (
        Path(sys.executable).resolve().parent
        if getattr(sys, "frozen", False)
        else Path(__file__).resolve().parent
    )
    try:
        file_handler = RotatingFileHandler(
            directory / "bridge.log", maxBytes=8 * 1024 * 1024, backupCount=4, encoding="utf-8"
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


# Public example: a length-prefixed JPEG datagram for your own receiver.
# This example does NOT implement any third-party application's private protocol.
EXAMPLE_ADAPTER = '''import struct
def encode_frame(channel, frame_id, jpeg_bytes):
    """Return a list of UDP datagrams (bytes).
    channel: 0=face, 1=left eye, 2=right eye (internal input labels)
    frame_id: monotonically increasing integer per channel (wrap is receiver-defined)
    jpeg_bytes: original complete JPEG frame; do not re-encode unless needed
    Use only a protocol you own, are authorized to use, or that is public.
    """
    # DEMONSTRATION ONLY: simple JPEG datagram for small images.
    # For larger images, design packet fragmentation for your own receiver.
    header = struct.pack("!BI", channel, len(jpeg_bytes))
    data = header + jpeg_bytes
    if len(data) > 60000:
        raise ValueError("Example adapter supports JPEGs <= 59995 bytes")
    return [data]
'''
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
        for channel in (CHANNEL_FACE, CHANNEL_LEFT, CHANNEL_RIGHT):
            value = saved.get(str(channel), {})
            value = value if isinstance(value, dict) else {}
            rotation = value.get("rotation", 0)
            if type(rotation) is not int or rotation not in (0, 90, 180, 270):
                rotation = 0
            self.values[channel] = (rotation, value.get("mirror", False) is True)

    def get(self, channel):
        with self.lock:
            return self.values[channel]

    def set(self, channel, rotation, mirror):
        with self.lock:
            self.values[channel] = (rotation, mirror)

    def apply(self, channel, jpeg):
        rotation, mirror = self.get(channel)
        if rotation == 0 and not mirror:
            return jpeg
        if not PIL_AVAILABLE:
            raise RuntimeError("카메라 회전·반전에는 Pillow가 필요합니다.")
        with Image.open(io.BytesIO(jpeg)) as original:
            image = original.convert("RGB")
            if rotation:
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


class PacketAdapter:
    def __init__(self, code, transforms=None):
        self.transforms = transforms
        self.code = code
        namespace = {"__name__": "user_packet_adapter"}
        # Executing user code is intentional: only load locally trusted code.
        exec(compile(code, "<packet-adapter>", "exec"), namespace)
        fn = namespace.get("encode_frame")
        if not callable(fn):
            raise ValueError("encode_frame(channel, frame_id, jpeg_bytes) 함수를 정의하세요.")
        self.fn = fn
        self.call_lock = threading.Lock()

    def send(self, sock, target, channel, frame_id, jpeg_bytes):
        if not jpeg_bytes:
            return 0
        started = time.monotonic()
        if self.transforms is not None:
            jpeg_bytes = self.transforms.apply(channel, jpeg_bytes)
        transformed = time.monotonic()
        with self.call_lock:
            acquired = time.monotonic()
            packets = self.fn(channel, frame_id, jpeg_bytes)
        encoded = time.monotonic()
        if not isinstance(packets, (list, tuple)):
            raise TypeError("encode_frame은 bytes 패킷의 목록을 반환해야 합니다.")
        if len(packets) > 65535:
            raise ValueError("한 프레임의 패킷 수가 너무 많습니다.")
        for packet in packets:
            if not isinstance(packet, bytes) or not 0 < len(packet) <= 65507:
                raise ValueError("각 패킷은 bytes 형식이며 크기는 1~65507바이트여야 합니다.")
            sock.sendto(packet, target)
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


class EyeSynchronizer:
    """Estimate right-minus-left motion lag, then delay ONLY the leading eye.
    For delta_t > 0 right arrives later, so left is delayed by delta_t.
    For delta_t < 0 left arrives later, so right is delayed by -delta_t.
    Original JPEG bytes, channels and independent frame IDs are preserved.
    """

    def __init__(self, sock, target, stop_event, stats, stats_lock, adapter, enabled=True):
        self.sock, self.target = sock, target
        self.adapter = adapter
        self.stop_event = stop_event
        self.stats, self.stats_lock = stats, stats_lock
        self.enabled = enabled
        self.cv = threading.Condition()
        self.queues = {CHANNEL_LEFT: deque(), CHANNEL_RIGHT: deque()}
        self.histories = {CHANNEL_LEFT: deque(maxlen=900), CHANNEL_RIGHT: deque(maxlen=900)}
        self.prev_image = {CHANNEL_LEFT: None, CHANNEL_RIGHT: None}
        self.offset = 0.0  # delta_t = right event arrival - left event arrival
        self.confidence = False
        self.last_calibrated_event = float("-inf")
        self.frame_ids = {CHANNEL_LEFT: 0, CHANNEL_RIGHT: 0}
        self.sent_frames = 0
        self.skipped = 0
        self.analysis_queues = {CHANNEL_LEFT: deque(maxlen=4), CHANNEL_RIGHT: deque(maxlen=4)}
        self.analysis_ms = 0.0
        self.calibration_ms = 0.0
        self.calibration_generation = 0
        self.thread = threading.Thread(target=self._run, daemon=True, name="eye-delay")
        self.calibration_thread = threading.Thread(
            target=self._calibrate, daemon=True, name="eye-calibration"
        )
        self.analysis_thread = threading.Thread(
            target=self._analyze, daemon=True, name="eye-motion"
        )

    def start(self):
        self.analysis_thread.start()
        self.thread.start()
        self.calibration_thread.start()

    def _calibrate(self):
        while not self.stop_event.is_set():
            started = time.perf_counter()
            self._estimate_offset()
            self.calibration_ms = (time.perf_counter() - started) * 1000
            self.stop_event.wait(0.5)

    def set_enabled(self, enabled):
        diagnostic("SYNC_CHANGED", enabled=bool(enabled))
        with self.cv:
            self.calibration_generation += 1
            self.enabled = bool(enabled)
            self.offset = 0.0
            self.confidence = False
            self.last_calibrated_event = float("-inf")
            for channel in self.histories:
                self.analysis_queues[channel].clear()
                self.histories[channel].clear()
                self.prev_image[channel] = None
            self.cv.notify_all()

    def reset_channel(self, channel):
        with self.cv:
            diagnostic(
                "SYNC_RESET",
                channel=channel,
                queued_discarded=len(self.queues[channel]),
                offset_ms=round(self.offset * 1000, 1),
            )
            self.calibration_generation += 1
            self.analysis_queues[channel].clear()
            self.queues[channel].clear()
            self.histories[channel].clear()
            self.prev_image[channel] = None
            self.confidence = False
            self.offset = 0.0
            self.last_calibrated_event = float("-inf")
            self.cv.notify_all()

    def _analyze(self):
        # Decode only in this worker; receiving and sending retain original bytes.
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
                    # Ask the JPEG decoder for a reduced grayscale image first.
                    im.draft("L", (48, 32))
                    gray = im.resize((48, 32)).convert("L")
                motion = (
                    ImageStat.Stat(ImageChops.difference(gray, previous)).mean[0]
                    if previous is not None
                    else None
                )
            except Exception:
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

    def add(self, channel, jpeg, timestamp):
        with self.cv:
            self.queues[channel].append((timestamp, jpeg))
            if PIL_AVAILABLE and self.enabled:
                self.analysis_queues[channel].append((timestamp, jpeg, self.calibration_generation))
            dropped = 0
            reasons = set()
            oldest_age = 0.0
            while self.queues[channel] and (
                len(self.queues[channel]) > 512 or timestamp - self.queues[channel][0][0] > 0.7
            ):
                reasons.add("queue_limit" if len(self.queues[channel]) > 512 else "stale_frame")
                oldest_age = max(oldest_age, timestamp - self.queues[channel][0][0])
                self.queues[channel].popleft()
                dropped += 1
            if dropped:
                self.skipped += dropped
                with self.stats_lock:
                    self.stats[channel].dropped += dropped
                    total = self.stats[channel].dropped
                diagnostic(
                    "FRAME_DROP",
                    logging.WARNING,
                    channel=channel,
                    source="enqueue",
                    count=dropped,
                    reasons=sorted(reasons),
                    oldest_ms=round(oldest_age * 1000, 1),
                    remaining=len(self.queues[channel]),
                    total=total,
                    sync_enabled=self.enabled,
                    offset_ms=round(self.offset * 1000, 1),
                )
            self.cv.notify_all()

    @staticmethod
    def _blink_candidates(samples):
        """Two short motion peaks are only blink candidates, not eye-state labels."""
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
            # Reject ambiguous/multiple strong transitions in the middle.
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
        # Keep the previous delta_t when no reliable bilateral blink is present.
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
        levents = self._blink_candidates(left)
        revents = self._blink_candidates(right)
        if not levents or not revents:
            return
        matches = []
        for ls, le, la in levents:
            if ls <= last_event:
                continue
            for rs, re, ra in revents:
                ds, de = rs - ls, re - le
                if max(abs(ds), abs(de)) > 0.30:
                    continue
                if abs(ds - de) > 0.065:
                    continue
                lag = (ds + de) / 2
                if confidence and abs(lag - offset) > 0.15:
                    continue
                score = self._local_correlation(left, right, lag, ls)
                if score < 0.65:
                    continue
                matches.append((score, min(la, ra), lag, ls))
        if not matches:
            return
        matches.sort(reverse=True)
        score, _strength, lag, event_time = matches[0]
        with self.cv:
            if generation != self.calibration_generation or not self.enabled:
                return
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
                # Delay only the channel whose event is observed earlier.
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
                        self.skipped += dropped
                        with self.stats_lock:
                            self.stats[ch].dropped += dropped
                            total = self.stats[ch].dropped
                        diagnostic(
                            "FRAME_DROP",
                            logging.WARNING,
                            channel=ch,
                            source="sender",
                            count=dropped,
                            reasons=["stale_frame"],
                            oldest_ms=round(oldest_age * 1000, 1),
                            remaining=len(q),
                            total=total,
                            sync_enabled=self.enabled,
                            offset_ms=round(offset * 1000, 1),
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
                self.sent_frames += 1
                with self.stats_lock:
                    st = self.stats[ch]
                    st.frames += 1
                    st.packets += count
                    st.last_frame_size = len(jpeg)
                    st.error = ""
            except Exception as exc:
                diagnostic(
                    "SEND_ERROR",
                    logging.ERROR,
                    channel=ch,
                    frame_id=frame_id,
                    jpeg_bytes=len(jpeg),
                    error=repr(exc),
                )
                with self.stats_lock:
                    self.stats[ch].error = f"패킷 코드 오류: {exc}"
                if not self.stop_event.is_set():
                    time.sleep(0.05)


class MJPEGWorker(threading.Thread):
    def __init__(
        self, name, url, channel, udp_socket, target, stop_event, stats, lock, synchronizer, adapter
    ):
        super().__init__(daemon=True, name=name)
        self.url, self.channel = url, channel
        self.udp_socket, self.target = udp_socket, target
        self.stop_event, self.stats, self.lock = stop_event, stats, lock
        self.synchronizer = synchronizer
        self.adapter = adapter
        self.frame_id = 0

    def set_stats(self, **kwargs):
        with self.lock:
            s = self.stats[self.channel]
            for key, value in kwargs.items():
                setattr(s, key, value)

    def run(self):
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
                # read(8192) can wait for all 8192 bytes. read1 returns
                # already-available bytes instead, avoiding spurious stalls.
                read_chunk = getattr(response, "read1", response.read)
                while not self.stop_event.is_set():
                    try:
                        read_started = time.monotonic()
                        chunk = read_chunk(8192)
                    except TimeoutError as exc:
                        raise ConnectionError(
                            "3초 동안 스트림 데이터가 수신되지 않았습니다."
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
                        now = time.monotonic()
                        with self.lock:
                            self.stats[self.channel].received += 1
                        if self.synchronizer and self.channel in (CHANNEL_LEFT, CHANNEL_RIGHT):
                            self.synchronizer.add(self.channel, jpeg, now)
                            # Receive counters are updated independently from matched/sent counters.
                            self.set_stats(connected=True, error="")
                        else:
                            count = self.adapter.send(
                                self.udp_socket, self.target, self.channel, self.frame_id, jpeg
                            )
                            self.frame_id = (self.frame_id + 1) & 0xFFFF
                            with self.lock:
                                st = self.stats[self.channel]
                                st.frames += 1
                                st.packets += count
                                st.last_frame_time = now
                                st.last_frame_size = len(jpeg)
                                st.error = ""
                        # Capture health for sync channels even when a pair is dropped.
                        if self.synchronizer and self.channel in (CHANNEL_LEFT, CHANNEL_RIGHT):
                            with self.lock:
                                self.stats[self.channel].last_frame_time = now
                    # Parse newly arrived data before deciding the stream stalled.
                    if time.monotonic() - last_complete_frame > READ_TIMEOUT:
                        raise ConnectionError("3초 동안 완전한 JPEG 프레임이 수신되지 않았습니다.")
            except Exception as exc:
                if self.stop_event.is_set():
                    break
                failure_time = time.monotonic()
                with self.lock:
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
                    retry=isinstance(exc, OSError),
                    retry_delay_s=retry_delay,
                )
                self.set_stats(connected=False, error=f"{type(exc).__name__}: {exc}")
                if self.synchronizer and self.channel in (CHANNEL_LEFT, CHANNEL_RIGHT):
                    self.synchronizer.reset_channel(self.channel)
                if not isinstance(exc, OSError):
                    break
                # Close before waiting and reopening only this failed channel.
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        pass
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
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        pass
        diagnostic(
            "STREAM_STOPPED",
            channel=self.channel,
            uptime_s=round(time.monotonic() - worker_started, 1),
            requested=self.stop_event.is_set(),
        )


class BridgeApp:
    STREAMS = (
        ("Face", CHANNEL_FACE, "http://nareface.local/face"),
        ("Left eye", CHANNEL_LEFT, "http://nareface.local/left"),
        ("Right eye", CHANNEL_RIGHT, "http://nareface.local/right"),
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
        self.workers = []
        self.synchronizer = None
        self.adapter = None
        self.adapter_code = ""
        self._last_ui_error = ""
        self._auto_start_timer = None
        self._auto_start_suspended = False
        self._editor_draft = None
        self.app_directory = (
            Path(sys.executable).resolve().parent
            if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parent
        )
        self.adapter_path = self.app_directory / "packet_adapter.json"
        self.settings_path = self.app_directory / "settings.json"
        self._settings_data = {}
        self._saved_port = None
        self._port_save_timer = None
        try:
            if self.settings_path.exists():
                data = json.loads(self.settings_path.read_text(encoding="utf-8-sig"))
                if isinstance(data, dict):
                    self._settings_data = data
                    port = data.get("port")
                    if type(port) is int and 1 <= port <= 65535:
                        self._saved_port = port
        except (OSError, ValueError, UnicodeError):
            pass
        programs = self._settings_data.get("programs", [])
        self.program_window = None
        self.program_list = None
        self.companion_programs = (
            [path for path in programs if isinstance(path, str) and path.strip()]
            if isinstance(programs, list)
            else []
        )
        self.editor_window = None
        self._settings_timer = None
        self._startup_error = None
        if self.adapter_path.exists():
            try:
                self.adapter_code = self.read_adapter_json(self.adapter_path)
            except Exception as exc:
                self._startup_error = self._error_message(exc)
        self.stats_lock = threading.Lock()
        self.stats = {ch: StreamStats() for _, ch, _ in self.STREAMS}
        self.prev_frames = {ch: 0 for _, ch, _ in self.STREAMS}
        self.prev_received = {ch: 0 for _, ch, _ in self.STREAMS}
        self.rx_fps_vars, self.drop_vars = {}, {}
        self._health_previous = {}
        self._health_baseline = {}
        self._health_degraded = set()
        self._session_start = time.monotonic()
        self._log_time = time.monotonic()
        self.prev_time = time.monotonic()
        self.frame_transforms = FrameTransforms(self._settings_data.get("camera_transforms"))
        self.rotation_vars, self.mirror_buttons = {}, {}
        self.url_vars, self.status_vars = {}, {}
        self.fps_vars, self.frame_vars, self.size_vars = {}, {}, {}
        self.sync_var = tk.BooleanVar(
            master=self.root, value=self._settings_data.get("eye_sync", True) is not False
        )
        self._build_ui()
        self.root.after(100, self._center_main_window)
        self.root.after(500, self._launch_companion_programs)
        for variable in (self.target_port_var, self.target_ip_var, *self.url_vars.values()):
            variable.trace_add("write", self._connection_settings_changed)
        self.target_port_var.trace_add("write", self._schedule_port_save)
        for variable in self.url_vars.values():
            variable.trace_add("write", self._save_stream_urls)
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

    @staticmethod
    def validate_adapter_code(code):
        if not isinstance(code, str) or not code.strip():
            raise ValueError("패킷 코드가 비어 있습니다.")
        tree = ast.parse(code)
        compile(tree, "<packet-adapter>", "exec")
        if not any(
            isinstance(node, ast.FunctionDef) and node.name == "encode_frame" for node in tree.body
        ):
            raise ValueError("encode_frame(channel, frame_id, jpeg_bytes) 함수를 정의하세요.")

    @classmethod
    def read_adapter_json(cls, path):
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("지원하지 않는 패킷 JSON 형식입니다. version: 1이 필요합니다.")
        code = data.get("code")
        if not isinstance(code, str):
            raise ValueError("JSON의 code는 문자열이어야 합니다.")
        if code.strip():
            cls.validate_adapter_code(code)
        return code

    def save_adapter_json(self, code):
        if code.strip():
            self.validate_adapter_code(code)
        data = {"version": 1, "name": "Custom UDP adapter", "code": code}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.adapter_path.parent,
                prefix=".packet-adapter-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.adapter_path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        self.adapter_code = code
        self._editor_draft = None
        self._auto_start_suspended = False
        self.adapter_status_var.set("JSON 저장 완료 · 다음 실행 시 자동 불러오기")
        self._refresh_adapter_readiness()

    def _build_ui(self):
        bg, panel, inset, line = "#0c1119", "#141d29", "#0e1621", "#263344"
        white, muted, accent = "#eef4fa", "#8c9eb3", "#ff8587"
        self.root.configure(bg=bg)
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
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=white, font=("맑은 고딕", 10))
        style.configure("Title.TLabel", font=("맑은 고딕", 24, "bold"), foreground=white)
        style.configure("Muted.TLabel", foreground=muted, font=("맑은 고딕", 9))
        style.configure(
            "TButton",
            font=("맑은 고딕", 10),
            padding=(14, 10),
            background="#223044",
            foreground=white,
            borderwidth=0,
        )
        style.map(
            "TButton",
            background=[("active", "#30435a"), ("disabled", "#182332")],
            foreground=[("disabled", "#65768c")],
        )
        style.configure(
            "Accent.TButton",
            background=accent,
            foreground="#321819",
            font=("맑은 고딕", 11, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("disabled", "#412b32"), ("active", "#ffa5a7")],
            foreground=[("disabled", "#9b7077")],
        )
        style.configure(
            "TEntry",
            padding=7,
            fieldbackground="#243247",
            foreground=white,
            insertcolor=white,
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            bordercolor="#243247",
            lightcolor="#243247",
            darkcolor="#243247",
        )
        style.map("TEntry", fieldbackground=[("focus", "#30435c")], bordercolor=[("focus", accent)])
        style.configure("TCheckbutton", background=panel, foreground=white, font=("맑은 고딕", 10))
        style.map("TCheckbutton", background=[("active", panel)])
        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", background=panel, foreground=muted, padding=(16, 10))
        style.map(
            "TNotebook.Tab", background=[("selected", "#25384a")], foreground=[("selected", accent)]
        )

        def label(parent, text=None, size=10, color=white, bold=False, **kw):
            return tk.Label(
                parent,
                text=text,
                bg=parent.cget("bg"),
                fg=color,
                font=("맑은 고딕", size, "bold" if bold else "normal"),
                **kw,
            )

        def card(parent):
            return tk.Frame(
                parent, bg=panel, highlightbackground=line, highlightthickness=1, padx=20, pady=12
            )

        outer = tk.Frame(self.root, bg=bg, padx=28, pady=14)
        outer.pack(fill="both", expand=True)
        self._main_content = outer
        self._fit_pending = None

        def schedule_fit(event=None):
            if self._fit_pending is None:
                self._fit_pending = self.root.after_idle(self._fit_main_window)

        outer.bind("<Configure>", schedule_fit)
        nav = tk.Frame(outer, bg=bg)
        nav.pack(fill="x", pady=(0, 12))
        nav.columnconfigure(1, weight=1)
        nav_labels = [
            label(nav, f"MJPEG / BRIDGE  v{APP_VERSION}", 13, bold=True),
            label(nav, "STREAM CONTROL STUDIO", 9, muted),
            label(nav, "●  로컬 처리", 10, accent),
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
            outer, height=294, bg="#0b1017", highlightthickness=1, highlightbackground=line
        )
        hero.pack(fill="x", pady=(0, 16))
        self._hero_original = None
        asset = self.app_directory / "assets" / "img.png"
        if asset.exists():
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
                resized = image.resize((width, int(image.height * scale)), Image.Resampling.LANCZOS)
                # Display at the requested 1780:427 ratio without distortion.
                top = max(0, int((resized.height - height) * 0.22))
                self._hero_photo = ImageTk.PhotoImage(resized.crop((0, top, width, top + height)))
                hero.create_image(0, 0, image=self._hero_photo, anchor="nw")
            elif hasattr(self, "_hero_photo"):
                hero.create_image(width, height // 2, image=self._hero_photo, anchor="e")
            hero.create_text(
                26,
                18,
                anchor="nw",
                text="CAPTURE. SYNC. SEND. [by '백설기@']",
                fill=accent,
                font=("Segoe UI", 10, "bold"),
            )
            hero.create_text(
                24,
                43,
                anchor="nw",
                text="나래 - 외부 Facial 브릿지",
                fill=white,
                font=("맑은 고딕", 26, "bold"),
            )
            hero.create_text(
                26,
                91,
                anchor="nw",
                text="브붕이들아 언제든 행복해야해~!!",
                fill="#afbfce",
                font=("맑은 고딕", 10),
            )
            hero.create_text(
                26,
                120,
                anchor="nw",
                text="JPEG ORIGINAL    /    EYE SYNC    /    CUSTOM PACKETS",
                fill="#7b91a5",
                font=("Segoe UI", 9),
            )

        hero.bind("<Configure>", draw_hero)

        body = tk.Frame(outer, bg=bg)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)
        streams = card(body)
        streams.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        heading = tk.Frame(streams, bg=panel)
        heading.pack(fill="x", pady=(0, 12))
        label(heading, "스트림 모니터", 15, bold=True).pack(side="left")
        label(heading, "3 CHANNELS", 9, muted).pack(side="right")
        self.status_labels = {}
        for name, ch, default_url in self.STREAMS:
            row = tk.Frame(
                streams, bg=inset, highlightbackground=line, highlightthickness=1, padx=14, pady=4
            )
            row.pack(fill="x", pady=(0, 10))
            top = tk.Frame(row, bg=inset)
            top.pack(fill="x", pady=(0, 6))
            label(top, ["◎", "◉", "◉"][ch], 17, accent).pack(side="left", padx=(0, 9))
            label(top, ["얼굴", "왼쪽 눈", "오른쪽 눈"][ch], 12, bold=True).pack(side="left")
            label(top, f"CH 0{ch + 1}", 9, muted).pack(side="left", padx=(12, 8))
            rotation, mirror = self.frame_transforms.get(ch)
            self.rotation_vars[ch] = tk.StringVar(value=f"↻ {rotation}°")
            rotation_button = tk.Button(
                top,
                textvariable=self.rotation_vars[ch],
                command=lambda channel=ch: self._change_camera_transform(channel, rotate=True),
                bg="#243247",
                fg=accent,
                activebackground="#30435c",
                activeforeground=white,
                relief="flat",
                borderwidth=0,
                highlightthickness=0,
                takefocus=False,
                font=("맑은 고딕", 9),
                padx=7,
                pady=2,
            )
            rotation_button.pack(side="left", padx=(0, 5))
            mirror_button = tk.Button(
                top,
                text="↔ 반전",
                command=lambda channel=ch: self._change_camera_transform(channel, mirror=True),
                bg=accent if mirror else "#243247",
                fg="#0c1119" if mirror else white,
                activebackground="#30435c",
                activeforeground=white,
                relief="flat",
                borderwidth=0,
                highlightthickness=0,
                takefocus=False,
                font=("맑은 고딕", 9),
                padx=7,
                pady=2,
            )
            mirror_button.pack(side="left")
            self.mirror_buttons[ch] = mirror_button
            if not PIL_AVAILABLE:
                rotation_button.configure(state="disabled")
                mirror_button.configure(state="disabled")
            self.status_vars[ch] = tk.StringVar(value="대기")
            status = label(top, size=9, color=muted, textvariable=self.status_vars[ch])
            status.pack(side="right")
            self.status_labels[ch] = status
            saved_urls = self._settings_data.get("stream_urls", {})
            saved_url = (
                saved_urls.get(str(ch), default_url)
                if isinstance(saved_urls, dict)
                else default_url
            )
            self.url_vars[ch] = tk.StringVar(
                value=saved_url if isinstance(saved_url, str) else default_url
            )
            ttk.Entry(row, textvariable=self.url_vars[ch]).pack(fill="x")
            metrics = tk.Frame(row, bg=inset)
            metrics.pack(fill="x", pady=(6, 0))
            self.fps_vars[ch] = tk.StringVar(value="0.0")
            self.frame_vars[ch] = tk.StringVar(value="0")
            self.size_vars[ch] = tk.StringVar(value="—")
            self.rx_fps_vars[ch] = tk.StringVar(value="0.0")
            self.drop_vars[ch] = tk.StringVar(value="0")
            for title, var in [
                ("수신 FPS", self.rx_fps_vars[ch]),
                ("전송 FPS", self.fps_vars[ch]),
                ("DROP", self.drop_vars[ch]),
                ("JPEG", self.size_vars[ch]),
            ]:
                label(metrics, title, 8, muted).pack(side="left", padx=(0, 7))
                label(metrics, size=10, textvariable=var).pack(side="left", padx=(0, 22))
        self._build_sync_settings(streams)

        right = tk.Frame(body, bg=bg)
        right.grid(row=0, column=1, sticky="nsew")
        packet = card(right)
        packet.pack(fill="x", pady=(0, 14))
        ph = tk.Frame(packet, bg=panel)
        ph.pack(fill="x")
        label(ph, "{ / }", 18, accent, True).pack(side="left")
        label(ph, "PACKET WORKSPACE", 9, muted).pack(side="right")
        label(packet, "사용자 지정 패킷", 17, bold=True).pack(anchor="w", pady=(8, 5))
        label(packet, "Python 코드 편집부터 JSON 저장 가능", 10, muted).pack(anchor="w")
        self.packet_btn = ttk.Button(
            packet,
            text="패킷 에디터 열기    ↗",
            style="Accent.TButton",
            command=self.open_packet_editor,
        )
        self.packet_btn.pack(fill="x", ipady=11, pady=(16, 10))
        ttk.Button(packet, text="↓  JSON 불러오기", command=self.load_adapter_json).pack(fill="x")
        self.adapter_status_var = tk.StringVar(value="저장하면 다음 실행 시 자동 복원됩니다.")
        label(
            packet,
            size=9,
            color=muted,
            textvariable=self.adapter_status_var,
            wraplength=390,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))

        target = card(right)
        target.pack(fill="x")
        label(target, "UDP 연결", 14, bold=True).pack(anchor="w", pady=(0, 10))
        fields = tk.Frame(target, bg=panel)
        fields.pack(fill="x")
        fields.columnconfigure(0, weight=3)
        fields.columnconfigure(1, weight=1)
        label(fields, "대상 IP", 9, muted).grid(row=0, column=0, sticky="w", pady=(0, 5))
        label(fields, "포트", 9, muted).grid(row=0, column=1, sticky="w", padx=(10, 0), pady=(0, 5))
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        self.target_port_var = tk.StringVar(
            value=str(self._saved_port if self._saved_port is not None else DEFAULT_PORT)
        )
        ttk.Entry(fields, textvariable=self.target_ip_var, width=18).grid(
            row=1, column=0, sticky="ew"
        )
        ttk.Entry(fields, textvariable=self.target_port_var, width=7).grid(
            row=1, column=1, sticky="ew", padx=(10, 0)
        )
        actions = tk.Frame(target, bg=panel)
        actions.pack(fill="x", pady=(14, 0))
        self.start_btn = ttk.Button(
            actions, text="▶  연결 시작", style="Accent.TButton", command=self.start
        )
        self.start_btn.pack(side="left", fill="x", expand=True, padx=(0, 7))
        self.stop_btn = ttk.Button(actions, text="정지", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 7))
        self.reconnect_btn = ttk.Button(
            actions, text="재연결", command=self.reconnect, state="disabled"
        )
        self.reconnect_btn.pack(side="left")

        companions = card(right)
        companions.pack(side="bottom", fill="x", pady=(14, 0))
        self.program_count_var = tk.StringVar(
            value=f"시작시 같이 실행될 프로그램 {len(self.companion_programs)}개"
        )
        label(companions, textvariable=self.program_count_var, size=11).pack(side="left")
        ttk.Button(companions, text="프로그램 관리", command=self.open_program_manager).pack(
            side="right"
        )

        footer = tk.Frame(outer, bg=bg)
        footer.pack(fill="x", pady=(10, 0))
        self.main_status_var = tk.StringVar()
        self.ready_indicator = label(footer, "●", 10, "#ff4f5e")
        self.ready_indicator.pack(side="left", padx=(0, 8))
        label(
            footer,
            size=9,
            color=muted,
            textvariable=self.main_status_var,
            wraplength=1030,
            justify="left",
        ).pack(side="left")
        label(footer, "UDP / MJPEG", 9, muted).pack(side="right")
        self._refresh_adapter_readiness()

    def _apply_window_icon(self, window):
        window.after_idle(lambda: self._theme_title_bar(window))
        assets = Path(__file__).resolve().parent / "assets"
        try:
            if not hasattr(self, "_app_icon") and (assets / "app_icon.png").exists():
                self._app_icon = tk.PhotoImage(master=self.root, file=str(assets / "app_icon.png"))
            if hasattr(self, "_app_icon"):
                window.iconphoto(True, self._app_icon)
            if os.name == "nt" and (assets / "app_icon.ico").exists():
                window.iconbitmap(str(assets / "app_icon.ico"))
        except tk.TclError:
            pass

    @staticmethod
    def _theme_title_bar(window):
        if os.name != "nt" or not window.winfo_exists():
            return
        import ctypes
        from ctypes import wintypes

        try:
            user = ctypes.windll.user32
            user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
            user.GetAncestor.restype = wintypes.HWND
            hwnd = user.GetAncestor(window.winfo_id(), 2)
            set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            set_attribute.argtypes = [
                wintypes.HWND,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_attribute.restype = ctypes.c_long
            dark = wintypes.BOOL(1)
            if set_attribute(hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark)) != 0:
                set_attribute(hwnd, 19, ctypes.byref(dark), ctypes.sizeof(dark))
            # Windows 11 caption, caption text, and window border colors (COLORREF).
            for attribute, color in [(35, 0x0019110C), (36, 0x00FAF4EE), (34, 0x00443326)]:
                value = wintypes.DWORD(color)
                set_attribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value))
        except (AttributeError, OSError, tk.TclError):
            pass

    def _change_camera_transform(self, channel, rotate=False, mirror=False):
        rotation, flipped = self.frame_transforms.get(channel)
        if rotate:
            rotation = (rotation + 90) % 360
        if mirror:
            flipped = not flipped
        settings = {
            str(ch): {"rotation": value[0], "mirror": value[1]}
            for ch in (CHANNEL_FACE, CHANNEL_LEFT, CHANNEL_RIGHT)
            for value in [self.frame_transforms.get(ch)]
        }
        settings[str(channel)] = {"rotation": rotation, "mirror": flipped}
        if not self._write_settings(dict(self._settings_data, camera_transforms=settings)):
            return
        self.frame_transforms.set(channel, rotation, flipped)
        self.rotation_vars[channel].set(f"↻ {rotation}°")
        self.mirror_buttons[channel].configure(
            bg="#ff8587" if flipped else "#243247", fg="#0c1119" if flipped else "#e6edf5"
        )
        diagnostic("CAMERA_TRANSFORM", channel=channel, rotation=rotation, mirror=flipped)

    def _save_stream_urls(self, *args):
        urls = {str(ch): variable.get() for ch, variable in self.url_vars.items()}
        if self._settings_data.get("stream_urls") != urls:
            self._write_settings(dict(self._settings_data, stream_urls=urls))

    def _schedule_port_save(self, *args):
        if self._port_save_timer is not None:
            self.root.after_cancel(self._port_save_timer)
        self._port_save_timer = self.root.after(500, self._save_port)

    def _save_port(self):
        self._port_save_timer = None
        try:
            port = int(self.target_port_var.get().strip())
        except ValueError:
            return
        if not 1 <= port <= 65535 or port == self._saved_port:
            return
        data = dict(self._settings_data, port=port)
        if self._write_settings(data):
            self._saved_port = port

    def _write_settings(self, data):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.settings_path.parent,
                prefix=".bridge-settings-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.settings_path)
            self._settings_data = data
            return True
        except OSError as exc:
            self._show_error("설정 저장 실패", self._error_message(exc), parent=self.root)
            return False
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

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
        win.configure(bg="#0c1119")
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
            background="#0e1621",
            fieldbackground="#0e1621",
            foreground="#eef4fa",
            rowheight=32,
            borderwidth=0,
            font=("맑은 고딕", 10),
        )
        style.map(
            "Programs.Treeview",
            background=[("selected", "#3d2933")],
            foreground=[("selected", "#ff8587")],
        )
        style.configure(
            "Programs.Treeview.Heading", background="#223044", foreground="#eef4fa", padding=8
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
        self.program_count_var.set(f"등록된 프로그램 {len(self.companion_programs)}개")
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
        if self._write_settings(dict(self._settings_data, programs=programs)):
            self.companion_programs = programs
            self._refresh_program_list()

    def _remove_companion_program(self):
        selected = self.program_list.selection()
        if not selected:
            return
        programs = list(self.companion_programs)
        del programs[int(selected[0])]
        if self._write_settings(dict(self._settings_data, programs=programs)):
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
        self._refresh_adapter_readiness()

    def _readiness_error(self):
        try:
            port = int(self.target_port_var.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            return "포트 번호를 1~65535 사이의 정수로 입력하세요."
        if not self.adapter_code.strip() or (
            self._editor_draft is not None and not self._editor_draft.strip()
        ):
            return "패킷 에디터에서 코드를 저장하거나 JSON을 불러오세요."
        if not self.target_ip_var.get().strip():
            return "UDP 대상 IP 주소를 입력하세요."
        if any(not var.get().strip() for var in self.url_vars.values()):
            return "모든 카메라 URL을 입력하세요."
        return ""

    def _auto_start(self):
        self._auto_start_timer = None
        if not self.workers and not self._readiness_error() and not self._auto_start_suspended:
            self.start()

    def _refresh_adapter_readiness(self, draft=None):
        self._last_ui_error = ""
        if draft is not None:
            self._editor_draft = draft
        reason = self._readiness_error()
        ready = not reason
        with self.stats_lock:
            runtime_error = bool(self.workers) and any(stats.error for stats in self.stats.values())
        self.ready_indicator.configure(fg="#ff4f5e" if runtime_error or not ready else "#74e3c2")
        if not ready:
            self._cancel_auto_start()
        if not self.workers:
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
        if any("가" <= char <= "힣" for char in detail):
            return detail
        return "패킷 코드 처리 중 오류가 발생했습니다.\n오류 상세: " + detail

    def _show_error(self, title, message, parent=None):
        self._last_ui_error = title
        self.ready_indicator.configure(fg="#ff4f5e")
        self.main_status_var.set("오류 · " + title)
        return self._show_dialog(title, message, parent, error=True)

    def _show_info(self, title, message, parent=None):
        return self._show_dialog(title, message, parent, error=False)

    def _show_dialog(self, title, message, parent=None, error=True):
        parent = parent or self.root
        win = tk.Toplevel(parent)
        self._apply_window_icon(win)
        win.withdraw()
        win.title(title)
        win.configure(bg="#0c1119")
        win.resizable(False, False)
        win.transient(parent)
        content = tk.Frame(win, bg="#0c1119", padx=26, pady=24)
        content.pack(fill="both", expand=True)
        badge = tk.Canvas(content, width=44, height=44, bg="#0c1119", highlightthickness=0)
        badge.pack(anchor="w", pady=(0, 12))
        badge.create_oval(2, 2, 42, 42, fill="#332128", outline="#ff8587", width=1)
        badge.create_text(
            22, 22, text="!" if error else "i", fill="#ff8587", font=("Segoe UI", 21, "bold")
        )
        tk.Label(
            content,
            text=title,
            bg="#0c1119",
            fg="#eef4fa",
            font=("맑은 고딕", 16, "bold"),
            wraplength=420,
            justify="left",
        ).pack(anchor="w")
        tk.Label(
            content,
            text=message,
            bg="#0c1119",
            fg="#aebccd",
            font=("맑은 고딕", 10),
            wraplength=420,
            justify="left",
        ).pack(anchor="w", pady=(10, 22))
        button = ttk.Button(content, text="확인", style="Accent.TButton", command=win.destroy)
        button.pack(anchor="e", ipadx=12)
        win.bind("<Return>", lambda event: win.destroy())
        win.bind("<Escape>", lambda event: win.destroy())
        win.update_idletasks()
        width = max(470, win.winfo_reqwidth())
        height = win.winfo_reqheight()
        x = max(0, parent.winfo_rootx() + (parent.winfo_width() - width) // 2)
        y = max(0, parent.winfo_rooty() + (parent.winfo_height() - height) // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
        previous = parent.grab_current()
        win.deiconify()
        win.grab_set()
        button.focus_set()
        parent.wait_window(win)
        if previous is not None and previous.winfo_exists():
            previous.grab_set()

    def _center_main_window(self):
        self._fit_main_window()
        self.root.update_idletasks()
        width, height = self.root.winfo_width(), self.root.winfo_height()
        left, top = 0, 0
        right, bottom = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class MonitorInfo(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("monitor", wintypes.RECT),
                    ("work", wintypes.RECT),
                    ("flags", wintypes.DWORD),
                ]

            user = ctypes.windll.user32
            user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
            user.GetAncestor.restype = wintypes.HWND
            user.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
            user.MonitorFromWindow.restype = wintypes.HANDLE
            user.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
            user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            hwnd = user.GetAncestor(self.root.winfo_id(), 2)
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

    def _build_sync_settings(self, parent):
        panel = tk.Frame(parent, bg="#141d29")
        panel.pack(fill="x", pady=(8, 0))
        tk.Frame(panel, bg="#263344", height=1).pack(fill="x", pady=(0, 12))
        row = tk.Frame(panel, bg="#141d29")
        row.pack(fill="x", pady=(0, 10))
        box = tk.Canvas(
            row,
            width=28,
            height=28,
            bg="#141d29",
            highlightthickness=0,
            takefocus=True,
            cursor="hand2",
        )
        box.pack(side="left", padx=(0, 10))
        self.sync_checkbox = box
        title = tk.Label(
            row,
            text="눈 좌우 딜레이 Sync (매우권장)",
            bg="#141d29",
            fg="#eef4fa",
            font=("맑은 고딕", 12, "bold"),
            cursor="hand2",
        )
        title.pack(side="left")

        def draw_box():
            box.delete("all")
            selected = self.sync_var.get()
            box.create_rectangle(
                3, 3, 25, 25, fill="#0e1621", outline="#ff8587" if selected else "#73859a", width=2
            )
            if selected:
                box.create_rectangle(8, 8, 20, 20, fill="#ff8587", outline="")
            if box.focus_get() == box:
                box.create_rectangle(0, 0, 27, 27, outline="#eef4fa", dash=(2, 2))

        def toggle(event=None):
            self.sync_var.set(not self.sync_var.get())
            self._apply_eye_sync()
            draw_box()
            self._update_settings_values()
            return "break"

        box.bind("<Button-1>", toggle)
        box.bind("<space>", toggle)
        box.bind("<Return>", toggle)
        box.bind("<FocusIn>", lambda event: draw_box())
        box.bind("<FocusOut>", lambda event: draw_box())
        title.bind("<Button-1>", toggle)
        draw_box()
        self.sync_value_vars = {key: tk.StringVar() for key in ("offset", "left", "right", "state")}
        tk.Label(
            row,
            textvariable=self.sync_value_vars["state"],
            bg="#141d29",
            fg="#8c9eb3",
            font=("맑은 고딕", 9),
        ).pack(side="right")
        metrics = tk.Frame(panel, bg="#141d29")
        metrics.pack(fill="x")
        for col, (key, title) in enumerate(
            [
                ("offset", "보정값 (오른쪽 − 왼쪽)"),
                ("left", "왼쪽 눈 지연"),
                ("right", "오른쪽 눈 지연"),
            ]
        ):
            metrics.columnconfigure(col, weight=1, uniform="sync")
            cell = tk.Frame(metrics, bg="#0e1621", padx=10, pady=8)
            cell.grid(row=0, column=col, sticky="ew", padx=(0, 8 if col < 2 else 0))
            tk.Label(cell, text=title, bg="#0e1621", fg="#8c9eb3", font=("맑은 고딕", 9)).pack(
                anchor="w"
            )
            tk.Label(
                cell,
                textvariable=self.sync_value_vars[key],
                bg="#0e1621",
                fg="#ff8587",
                font=("맑은 고딕", 14, "bold"),
            ).pack(anchor="w", pady=(3, 0))
        self._poll_settings()

    def _apply_eye_sync(self):
        enabled = self.sync_var.get()
        self._write_settings(dict(self._settings_data, eye_sync=enabled))
        if self.synchronizer is not None:
            self.synchronizer.set_enabled(enabled)
            if not enabled and self.workers:
                # Reopen HTTP streams to discard data buffered while analysis lagged.
                self.root.after_idle(self.reconnect)

    def _update_settings_values(self):
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

    def _poll_settings(self):
        self._update_settings_values()
        self._settings_timer = self.root.after(200, self._poll_settings)

    def _close_settings(self):
        if self._settings_timer is not None:
            self.root.after_cancel(self._settings_timer)
            self._settings_timer = None

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
            new_code = self.read_adapter_json(path)
            if editor is not None:
                editor.delete("1.0", "end")
                editor.insert("1.0", new_code)
            else:
                # Persist the selection as the default for the next startup.
                self.save_adapter_json(new_code)
                self.adapter_status_var.set("JSON 불러오기 완료 · 기본 파일에 저장됨")
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
        win.title("패킷 에디터 · JSON 자동 저장")
        win.geometry("1000x760")
        win.minsize(900, 650)
        win.transient(self.root)
        win.configure(bg="#0c1119")
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

        def code_changed(event=None):
            if code.edit_modified():
                self._refresh_adapter_readiness(code.get("1.0", "end-1c"))
                code.edit_modified(False)

        code.bind("<<Modified>>", code_changed)

        def close_editor():
            win.destroy()
            self._editor_draft = None
            self._refresh_adapter_readiness()

        win.protocol("WM_DELETE_WINDOW", close_editor)
        guide = tk.Text(
            guide_tab,
            font=("Consolas", 11),
            wrap="word",
            padx=14,
            pady=14,
            relief="flat",
            bg="#141d29",
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
            except Exception as exc:
                self._show_error("저장 실패", self._error_message(exc), parent=win)

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
                    self.validate_adapter_code(new_code)
                    code.delete("1.0", "end")
                    code.insert("1.0", new_code)
                    info.set("Python 코드 불러오기 완료 · JSON 저장을 눌러 적용하세요.")
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
        if self.workers:
            return
        if not self.adapter_code.strip():
            self._refresh_adapter_readiness()
            self._show_error(
                "준비 안 됨",
                "패킷 에디터에서 코드를 저장하거나 JSON을 불러오세요.",
                parent=self.root,
            )
            return
        try:
            port = int(self.target_port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self._show_error(
                "포트 번호를 확인하세요",
                "포트 번호는 1부터 65535 사이의 정수로 입력하세요.\n예: 5000",
            )
            return
        target_ip = self.target_ip_var.get().strip()
        if not target_ip:
            self._show_error(
                "대상 주소를 확인하세요",
                "UDP 데이터를 받을 대상 IP 주소를 입력하세요.\n예: 127.0.0.1",
            )
            return
        urls = {ch: self.url_vars[ch].get().strip() for _, ch, _ in self.STREAMS}
        if any(not u for u in urls.values()):
            self._show_error(
                "카메라 주소를 확인하세요",
                "비어 있는 카메라 주소가 있습니다.\n얼굴, 왼쪽 눈, 오른쪽 눈의 MJPEG URL을 모두 입력하세요.",
            )
            return
        try:
            self.adapter = PacketAdapter(self.adapter_code, self.frame_transforms)
            test = self.adapter.fn(0, 0, b"\xff\xd8\xff\xd9")
            if not isinstance(test, (list, tuple)) or not all(
                isinstance(p, bytes) and 0 < len(p) <= 65507 for p in test
            ):
                raise ValueError("encode_frame은 UDP 패킷(bytes)의 목록을 반환해야 합니다.")
        except Exception as exc:
            self._show_error("패킷 코드를 확인하세요", self._error_message(exc))
            return
        self._health_previous.clear()
        self._health_baseline.clear()
        self._health_degraded.clear()
        self._session_start = time.monotonic()
        self._log_time = self._session_start
        diagnostic(
            "SESSION_START", target_ip=target_ip, port=port, sync_enabled=self.sync_var.get()
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stop_event = threading.Event()
        self._last_ui_error = ""
        target = (target_ip, port)
        with self.stats_lock:
            self.stats = {ch: StreamStats() for _, ch, _ in self.STREAMS}
            self.prev_frames = {ch: 0 for _, ch, _ in self.STREAMS}
            self.prev_received = {ch: 0 for _, ch, _ in self.STREAMS}
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
        if self.synchronizer:
            self.synchronizer.start()
        self.workers = []
        for name, ch, _ in self.STREAMS:
            worker = MJPEGWorker(
                name,
                urls[ch],
                ch,
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
        self.main_status_var.set(
            f"Running -> {target_ip}:{port} | custom adapter | manual reconnect"
        )

    def reconnect(self):
        """Destroy old MJPEG HTTP sessions, sync state and UDP socket, then start fresh."""
        diagnostic("MANUAL_RECONNECT")
        if not self.workers:
            self.start()
            return
        self.main_status_var.set("모든 카메라 연결을 다시 시작하는 중입니다.")
        self.stop()
        # If a worker has not exited, do not run a second bridge on the same resources.
        if self.workers:
            self.main_status_var.set("재연결 전에 기존 연결이 종료되기를 기다리는 중입니다.")
            self._reconnect_pending = True
            return
        self.start()

    def stop(self):
        if self.workers and self.stop_event is not None and not self.stop_event.is_set():
            diagnostic("SESSION_STOP", uptime_s=round(time.monotonic() - self._session_start, 1))
        self._cancel_auto_start()
        self._auto_start_suspended = True
        if self.stop_event is not None:
            self.stop_event.set()
        for worker in self.workers:
            worker.join(timeout=3.5)
        if self.synchronizer is not None:
            with self.synchronizer.cv:
                self.synchronizer.cv.notify_all()
            self.synchronizer.thread.join(timeout=1.0)
            self.synchronizer.calibration_thread.join(timeout=1.0)
            self.synchronizer.analysis_thread.join(timeout=1.0)
        alive = [worker for worker in self.workers if worker.is_alive()]
        if alive or (
            self.synchronizer is not None
            and (
                self.synchronizer.thread.is_alive()
                or self.synchronizer.calibration_thread.is_alive()
                or self.synchronizer.analysis_thread.is_alive()
            )
        ):
            self.main_status_var.set("정지 중 · 카메라 연결이 종료되기를 기다립니다.")
            self.root.after(300, self.stop)
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
        self.main_status_var.set("Stopped")
        self._refresh_adapter_readiness()
        for _, ch, _ in self.STREAMS:
            self.status_vars[ch].set("Stopped")
            self.fps_vars[ch].set("0.0")
        if self._reconnect_pending:
            self._reconnect_pending = False
            self.root.after(0, self.start)

    def _update_ui(self):
        now = time.monotonic()
        dt = max(now - self.prev_time, 0.001)
        with self.stats_lock:
            snapshot = {ch: StreamStats(**vars(s)) for ch, s in self.stats.items()}
        for _, ch, _ in self.STREAMS:
            s = snapshot[ch]
            fps = (s.frames - self.prev_frames.get(ch, 0)) / dt
            self.fps_vars[ch].set(f"{fps:.1f}")
            self.rx_fps_vars[ch].set(f"{(s.received - self.prev_received.get(ch, 0)) / dt:.1f}")
            self.drop_vars[ch].set(str(s.dropped))
            self.prev_received[ch] = s.received
            self.frame_vars[ch].set(str(s.frames))
            self.size_vars[ch].set(
                f"{s.last_frame_size / 1024:.1f} KiB" if s.last_frame_size else "-"
            )
            if not self.workers:
                status = "대기"
            elif s.error:
                status = "● 오류: " + s.error[:20]
            elif not s.connected:
                status = "오류: " + s.error[:20] if s.error else "연결 중..."
            else:
                age = now - s.last_frame_time if s.last_frame_time else 999
                status = "● 전송 중" if age < 2 else "응답 대기 · 재연결"
            self.status_vars[ch].set(status)
            self.status_labels[ch].configure(
                fg="#ff8587"
                if status == "● 전송 중"
                else "#d14c60"
                if s.error and self.workers
                else "#8c9eb3"
            )
            self.prev_frames[ch] = s.frames
        self.prev_time = now
        errors = [
            (name, snapshot[ch].error)
            for name, ch, _ in self.STREAMS
            if self.workers and snapshot[ch].error
        ]
        if errors or self._last_ui_error:
            self.ready_indicator.configure(fg="#ff4f5e")
            self.main_status_var.set(
                "오류 · "
                + (
                    " / ".join(name + ": " + error[:55] for name, error in errors)
                    if errors
                    else self._last_ui_error
                )
            )
        elif self.workers:
            self.ready_indicator.configure(fg="#ff4f5e" if self._readiness_error() else "#74e3c2")
        if self.synchronizer and not errors and not self._last_ui_error:
            sync = self.synchronizer
            self.main_status_var.set(
                f"자동 재연결 | Eye delay: {sync.sent_frames} frames, "
                f"delta_t (R-L) {sync.offset * 1000:+.0f} ms "
                f"({'motion-calibrated' if sync.confidence else 'arrival-based'}), "
                f"dropped {sync.skipped} | Pillow {'ON' if PIL_AVAILABLE else 'not installed'}"
            )
        if self.workers and now - self._log_time >= 5.0:
            elapsed = now - self._log_time
            self._log_time = now
            rates = {}
            for channel, state in snapshot.items():
                previous = self._health_previous.get(channel, (0, 0))
                rates[channel] = {
                    "rx": round((state.received - previous[0]) / elapsed, 2),
                    "tx": round((state.frames - previous[1]) / elapsed, 2),
                }
                self._health_previous[channel] = (state.received, state.frames)
                for direction, fps in rates[channel].items():
                    key = (channel, direction)
                    baseline = self._health_baseline.get(key, fps)
                    if baseline >= 5 and fps < baseline * 0.7:
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
                        self._health_degraded.add(key)
                    elif key in self._health_degraded:
                        if fps >= baseline * 0.85:
                            diagnostic(
                                "FPS_RECOVERED",
                                channel=channel,
                                direction=direction,
                                fps=fps,
                                baseline_fps=round(baseline, 2),
                            )
                            self._health_degraded.discard(key)
                    else:
                        self._health_baseline[key] = baseline * 0.8 + fps * 0.2
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
                        "tx_fps": self.fps_vars[ch].get(),
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
        self.root.after(500, self._update_ui)

    def _on_close(self):
        if self._port_save_timer is not None:
            self.root.after_cancel(self._port_save_timer)
            self._port_save_timer = None
        self._save_port()
        self._cancel_auto_start()
        self._close_settings()
        self.stop()
        self.root.destroy()


if __name__ == "__main__":
    configure_diagnostics()
    root = tk.Tk()
    BridgeApp(root)
    root.mainloop()
