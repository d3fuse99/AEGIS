import queue
import threading

class EventBus:
    def __init__(self):
        self._subscribers = {}
        self._lock = threading.Lock()
        self._sse_clients = []
        self._sse_lock = threading.Lock()

    def subscribe(self, event_type, callback):
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)

    def publish(self, event_type, data):
        with self._lock:
            callbacks = list(self._subscribers.get(event_type, []))
            wildcard_callbacks = list(self._subscribers.get("*", []))

        for cb in callbacks + wildcard_callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

        self.broadcast_sse({"type": event_type, "data": data})

    def register_sse_client(self):
        q = queue.Queue(maxsize=100)
        with self._sse_lock:
            self._sse_clients.append(q)
        return q

    def unregister_sse_client(self, q):
        with self._sse_lock:
            if q in self._sse_clients:
                self._sse_clients.remove(q)

    def broadcast_sse(self, message):
        with self._sse_lock:
            dead_clients = []
            for client in self._sse_clients:
                try:
                    client.put_nowait(message)
                except queue.Full:
                    dead_clients.append(client)
            for dead in dead_clients:
                self._sse_clients.remove(dead)

bus = EventBus()