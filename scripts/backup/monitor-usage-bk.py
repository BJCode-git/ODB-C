import argparse
import psutil
from psutil import Process, cpu_count, cpu_times, cpu_percent, virtual_memory, net_io_counters
from sys import exit
from threading import Thread
from queue import Queue
from time import sleep, perf_counter
import csv

Worker_queue = Queue()
stop_logging = False  # Flag global pour arrêter proprement le thread de log

def delta_cpu_time(t1, t0):
    return (
        (t1.user - t0.user) +
        (t1.system - t0.system) +
        (t1.nice - t0.nice if t1.nice is not None else 0) +
        (t1.irq - t0.irq if t1.irq is not None else 0) +
        (t1.softirq - t0.softirq if t1.softirq is not None else 0) +
        (t1.steal - t0.steal if hasattr(t1, "steal") else 0)
    )

def delta_cpu_busy_time(t1, t0):
    idle = (t1.idle - t0.idle)
    iowait = (t1.iowait - t0.iowait) if hasattr(t1, "iowait") else 0
    total = sum((getattr(t1, f) - getattr(t0, f)) for f in t1._fields if hasattr(t0, f))
    return total - idle - iowait

def compute_rel_pid_percent(pid_delta_time, sys_delta_time, ncpu):
    if sys_delta_time == 0:
        return 0.0
    return 100.0 * pid_delta_time / (sys_delta_time * ncpu)

def compute_single_core_percent(pid_delta_time, core_delta_time):
    if core_delta_time == 0:
        return 0.0
    return 100.0 * pid_delta_time / core_delta_time

def compute_core_total_percent(core_busy_time, interval):
    if interval == 0:
        return 0.0
    return 100.0 * core_busy_time / interval

def set_cpu_affinity_recursively(pid, core):
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity([core])
        for child in proc.children(recursive=True):
            child.cpu_affinity([core])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def log_values(logdir, filename_pattern, pids):
    f_sys = open(f"{logdir}/{filename_pattern}_sys.csv", "w", newline="")
    writer_sys_cpu = csv.writer(f_sys)
    writer_sys_cpu.writerow(["Total_CPU_percent", "Total_Memory_percent"])

    f_sys_io = open(f"{logdir}/{filename_pattern}_sys_io.csv", "w", newline="")
    writer_sys_io = csv.writer(f_sys_io)
    writer_sys_io.writerow(["Bytes_sent", "Bytes_received"])

    f_pid_files = {}
    writer_pids_cpu = {}
    writer_pids_io = {}

    for pid in pids:
        f_cpu = open(f"{logdir}/{filename_pattern}_{pid}.csv", "w", newline="")
        writer = csv.writer(f_cpu)
        writer.writerow(["CPU_%_global", "CPU_%_on_core", "CPU_percent_core_pin", "Core", "Memory_%"])
        f_pid_files[pid] = f_cpu
        writer_pids_cpu[pid] = writer

        f_io = open(f"{logdir}/{filename_pattern}_{pid}_io.csv", "w", newline="")
        writer = csv.writer(f_io)
        writer.writerow(["Bytes_sent", "Bytes_received"])
        writer_pids_io[pid] = writer

    while not stop_logging or not Worker_queue.empty():
        try:
            l_sys_info, l_pids_info = Worker_queue.get(timeout=0.5)
        except:
            continue

        if l_sys_info is not None:
            writer_sys_cpu.writerow(l_sys_info[0])
            writer_sys_io.writerow(l_sys_info[1])

        if l_pids_info is not None:
            for pid, l_pid_info in l_pids_info.items():
                writer_pids_cpu[pid].writerow(l_pid_info[:5])
                writer_pids_io[pid].writerow(l_pid_info[5])

    f_sys.close()
    f_sys_io.close()
    for f in f_pid_files.values():
        f.close()

def monitor(logdir, filename_pattern, period=100, duration=100, pids=[], pin=-1):
    global stop_logging
    time_elapsed = 0
    log_thread = Thread(target=log_values, args=(logdir, filename_pattern, pids))
    log_thread.start()

    processes = [{pid: Process(pid)} for pid in pids]
    if pin != -1:
        for pid in pids:
            set_cpu_affinity_recursively(pid, pin)

    last_sys_time = psutil.cpu_times()
    last_cores_times = psutil.cpu_times(percpu=True)
    last_pid_times = {pid: processes[i][pid].cpu_times() for i, pid in enumerate(pids)}

    ncpu = psutil.cpu_count(logical=True)
    total_measures = 0

    while time_elapsed < duration:
        total_measures += 1
        start = perf_counter()
        sleep(period / 1000)

        if pin != -1:
            for pid in pids:
                set_cpu_affinity_recursively(pid, pin)

        sys_cpu_times = psutil.cpu_times()
        sys_delta_time = delta_cpu_time(sys_cpu_times, last_sys_time)
        last_sys_time = sys_cpu_times

        cpu_percent_global = psutil.cpu_percent(interval=None)
        mem = virtual_memory()
        net = net_io_counters()

        current_cores_times = psutil.cpu_times(percpu=True)
        core_busy_time_total = 0.0
        for c_new, c_old in zip(current_cores_times, last_cores_times):
            core_busy_time_total += delta_cpu_busy_time(c_new, c_old)

        if pin != -1:
            core_busy_time_pin = delta_cpu_busy_time(current_cores_times[pin], last_cores_times[pin])
            cpu_percent_core_pin = 100.0 * core_busy_time_pin / core_busy_time_total if core_busy_time_total > 0 else 0.0
        else:
            cpu_percent_core_pin = None
            core_busy_time_pin = None

        last_cores_times = current_cores_times

        core = pin if pin != -1 else None

        l_sys = [cpu_percent_global, mem.percent]
        l_sys_io = [net.bytes_sent, net.bytes_recv]

        l_pids = dict()
        for i, pid in enumerate(pids):
            p = processes[i][pid]
            try:
                cur_pid_time = p.cpu_times()
                pid_delta = (
                    (cur_pid_time.user - last_pid_times[pid].user) +
                    (cur_pid_time.system - last_pid_times[pid].system)
                )
                last_pid_times[pid] = cur_pid_time

                cpu_percent_total = compute_rel_pid_percent(pid_delta, sys_delta_time, ncpu)

                if pin != -1 and core_busy_time_pin and core_busy_time_pin > 0:
                    cpu_percent_on_core = 100.0 * pid_delta / core_busy_time_pin
                else:
                    cpu_percent_on_core = None

                mem_percent = p.memory_percent()
                io = p.io_counters()
                l_pids[pid] = [cpu_percent_total, cpu_percent_on_core, cpu_percent_core_pin, core, mem_percent, [io.write_bytes,io.read_bytes]]

            except psutil.NoSuchProcess:
                continue

        Worker_queue.put([[l_sys, l_sys_io], l_pids])
        time_elapsed += perf_counter() - start

    stop_logging = True
    log_thread.join()
    print("Monitoring finished, time elapsed:", time_elapsed, "s", "measures:", total_measures)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Monitor system and process CPU/memory usage.")
    parser.add_argument("logdir", help="Directory to log to")
    parser.add_argument("filename_pattern", help="Prefix for log filenames")
    parser.add_argument("--period", type=int, default=100, help="Monitoring period in ms")
    parser.add_argument("--duration", type=int, default=100, help="Monitoring duration in seconds")
    parser.add_argument("--pids", nargs='+', type=int, default=[], help="List of PIDs to monitor")
    parser.add_argument("--pin", type=int, default=-1, help="Core to pin processes to")
    args = parser.parse_args()

    if args.period <= 0 or args.duration <= 0:
        print("[ERROR] Period and duration must be > 0")
        exit(1)

    cpu_logical_cores = cpu_count(logical=True)
    if cpu_logical_cores is None:
        print("[ERROR] Unable to get logical CPU count")
        exit(1)

    if args.pin >= cpu_logical_cores:
        print(f"[ERROR] Pin must be between 0 and {cpu_logical_cores - 1}")
        args.pin = -1

    monitor(args.logdir, args.filename_pattern, args.period, args.duration, args.pids, args.pin)
    exit(0)
