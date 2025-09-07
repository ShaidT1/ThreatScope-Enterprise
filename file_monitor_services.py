from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import asyncio
import queue
import threading
from typing import Callable
import logging
from scapy.utils import PcapReader
from scapy.all import TCP, IP, Raw
import json

logger = logging.getLogger(__name__)

class FileMonitoringService:
    def __init__(self, event_processor: Callable):
        self.event_processor = event_processor
        self.observer = Observer()
        self.work_queue = queue.Queue(maxsize=1000)
        self.work_thread = None
        self.running = False

    def start_monitoring(self, watch_path: str, file_types: str):
        """Start monitoring folder for given file types."""
        self.running = True
        file_types_list = file_types.split(",")

        # Start worker thread if not already running
        if not self.work_thread or not self.work_thread.is_alive():
            self.work_thread = threading.Thread(target=self.worker_queue, daemon=True)
            self.work_thread.start()

        # Schedule handlers
        if "json" in file_types_list:
            self.observer.schedule(JsonHandler(self.work_queue), watch_path, recursive=False)
        if "pcap" in file_types_list:
            self.observer.schedule(PcapHandler(self.work_queue), watch_path, recursive=False)
        if "log" in file_types_list:
            self.observer.schedule(LogHandler(self.work_queue), watch_path, recursive=False)

        self.observer.start()
        logger.info(f"Started monitoring: {file_types_list} Folder: {watch_path}")
        return {"status": "monitoring started", "folder": watch_path, "types": file_types_list}

    def stop_monitoring(self):
        self.running = False

        if hasattr(self, "observer") and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=5)

        if self.work_thread and self.work_thread.is_alive():
            self.work_thread.join(timeout=5)

        logger.info("Stopped monitoring")

    def worker_queue(self):
        while self.running:
            try:
                source_type, content = self.work_queue.get(timeout=1)
                # Safely schedule async task in the running loop
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.event_processor(source_type, content), loop)
                else:
                    asyncio.run(self.event_processor(source_type, content))
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker queue error: {e}")

# Handlers
class JsonHandler(FileSystemEventHandler):
    def __init__(self, worker_queue: queue.Queue):
        self.worker_queue = worker_queue

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        try:
            with open(event.src_path, "r") as f:
                data = json.load(f)
            self.worker_queue.put_nowait(("json", data))
        except Exception as e:
            logger.error(e)


class LogHandler(FileSystemEventHandler):
    def __init__(self, worker_queue: queue.Queue):
        self.worker_queue = worker_queue

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        if event.is_directory or not event.src_path.endswith(".log"):
            return
        try:
            with open(event.src_path, "r") as f:
                content = f.read().strip()
            if content:
                self.worker_queue.put_nowait(("log", content))
        except Exception as e:
            logger.error(e)


class PcapHandler(FileSystemEventHandler):
    def __init__(self, worker_queue: queue.Queue):
        self.worker_queue = worker_queue

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        if event.is_directory or not event.src_path.endswith(".pcap"):
            return
        try:
            with PcapReader(event.src_path) as pcap:
                for packet in pcap:
                    if packet.haslayer(TCP) and packet.haslayer(IP) and packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode(errors="ignore")
                            if payload:
                                self.worker_queue.put_nowait(("pcap", payload))
                        except Exception as e:
                            logger.error(e)
        except Exception as e:
            logger.error(e)
