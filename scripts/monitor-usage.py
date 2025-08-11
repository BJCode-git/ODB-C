import argparse
import psutil
from psutil import Process, cpu_count, cpu_times, cpu_percent, virtual_memory, net_io_counters
from sys import exit
from os import makedirs
from threading import Thread
from queue import Queue
from time import sleep, perf_counter
import csv

Worker_queue = Queue()
stop_logging = False  # Flag global pour arrêter proprement le thread de log


def set_cpu_affinity_recursively(pid, core):
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity([core])
        for child in proc.children(recursive=True):
            child.cpu_affinity([core])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def log_values(logdir, filename_pattern, pids):
    
    #make dir if not exist
    makedirs(logdir, exist_ok=True)
    
    f_sys = open(f"{logdir}/{filename_pattern}_sys.csv", "w", newline="")
    writer_sys_cpu = csv.writer(f_sys)
    writer_sys_cpu.writerow(["Total_CPU_percent", "Total_Memory_usage"])

    f_sys_io = open(f"{logdir}/{filename_pattern}_sys_io.csv", "w", newline="")
    writer_sys_io = csv.writer(f_sys_io)
    writer_sys_io.writerow(["Bytes_sent", "Bytes_received"])

    f_pid_files = {}
    writer_pids_cpu = {}
    writer_pids_io = {}

    for pid in pids:
        f_cpu = open(f"{logdir}/{filename_pattern}_{pid}.csv", "w", newline="")
        writer = csv.writer(f_cpu)
        writer.writerow(["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process", "Core", "Process_memory_usage"])
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
    core = None
    ncpu = cpu_count(logical=True)
    if pin != -1:
        core = pin
        for pid in pids:
            set_cpu_affinity_recursively(pid, pin)

    total_measures = 0
    while time_elapsed < duration:
        total_measures += 1
        start = perf_counter()
        sleep(period / 1000)

        cpu_percent_global = cpu_percent(interval=None)
        mem = virtual_memory()
        tot_mem_usage = mem.total - mem.available
        net = net_io_counters()

        cpu_core_percent = cpu_percent(interval=None, percpu=True)[pin] if pin != -1 else None
        
        l_sys = [cpu_percent_global, tot_mem_usage]
        l_sys_io = [net.bytes_sent, net.bytes_recv]

        l_pids = dict()
        for i, pid in enumerate(pids):
            p = processes[i][pid]
            try:
                cpu_pid_percent = p.cpu_percent(interval=None) / ncpu
                pid_mem_usage = p.memory_full_info().uss
                
                io = p.io_counters()
                l_pids[pid] = [cpu_percent_global,cpu_core_percent, cpu_pid_percent, core,pid_mem_usage, [io.write_bytes,io.read_bytes]]

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
