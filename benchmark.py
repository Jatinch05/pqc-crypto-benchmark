import time
import psutil

class Benchmark:
    def __init__(self):
        self.process = psutil.Process()

    def start(self):
        self.start_time   = time.perf_counter()
        self.start_cpu    = self.process.cpu_percent(interval=None)
        self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB

    def stop(self):
        end_time   = time.perf_counter()
        end_cpu    = self.process.cpu_percent(interval=None)
        end_memory = self.process.memory_info().rss / 1024 / 1024

        time_taken  = (end_time - self.start_time) * 1000  # ms
        cpu_usage   = (end_cpu - self.start_cpu) if end_cpu > self.start_cpu else end_cpu
        memory_diff = end_memory - self.start_memory

        print(f"Memory Usage - Start: {self.start_memory:.2f} MB, "
              f"End: {end_memory:.2f} MB, Diff: {memory_diff:.2f} MB")

        return {
            'time_taken':     f"{time_taken:.2f} ms",
            'cpu_usage':      f"{cpu_usage:.2f} %",
            'memory_diff':    f"{memory_diff:.2f} MB",
            'memory_absolute': f"{end_memory:.2f} MB"
        }
