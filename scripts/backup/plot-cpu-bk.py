import sys
import os
import numpy as np
import matplotlib.pyplot as plt
import argparse
from statistics import mean, median, quantiles

def moving_average(data, window_size):
    if window_size < 2 or len(data) < window_size:
        return np.array(data)
    return np.convolve(data, np.ones(window_size)/window_size, mode='valid')

def parse_psrecord_log(filepath):
    times = []
    cpu_percent = []
    mem_mb = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                parts = line.split()
                if len(parts) < 3:
                    continue  # ligne incomplète
                t = float(parts[0])
                cpu = float(parts[1])
                mem = float(parts[2])
                times.append(t)
                cpu_percent.append(cpu)
                mem_mb.append(mem)
            except ValueError:
                print(f"[WARN] Ligne ignorée : {line}")
                continue

    if not times:
        raise ValueError(f"[ERREUR] Aucune donnée valide dans le fichier : {filepath}")
    
    return np.array(times), np.array(cpu_percent), np.array(mem_mb)


def describe(data):
    return {
        "mean": mean(data),
        "median": median(data),
        "Q1": quantiles(data, n=4)[0],
        "Q3": quantiles(data, n=4)[2],
    }

def plot_smoothed_data(time, cpu, mem, window, output_file):
    smoothed_cpu = moving_average(cpu, window)
    smoothed_mem = moving_average(mem, window)
    smoothed_time = time[:len(smoothed_cpu)]

    stats_cpu = describe(cpu)
    stats_mem = describe(mem)

    plt.figure(figsize=(12, 6))
    plt.plot(smoothed_time, smoothed_cpu, label='CPU (%)', color='tab:red')
    plt.plot(smoothed_time, smoothed_mem, label='Mémoire (MB)', color='tab:blue')

    # Lignes stats CPU
    plt.axhline(stats_cpu['mean'], linestyle='--', color='tab:red', alpha=0.4, label='Moy CPU')
    plt.axhline(stats_cpu['median'], linestyle='--', color='darkorange', alpha=0.4, label='Med CPU')
    plt.axhline(stats_cpu['Q1'], linestyle=':', color='gray', alpha=0.4, label='Q1 CPU')
    plt.axhline(stats_cpu['Q3'], linestyle=':', color='gray', alpha=0.4, label='Q3 CPU')

    # Lignes stats MEM
    plt.axhline(stats_mem['mean'], linestyle='--', color='tab:blue', alpha=0.4, label='Moy MEM')
    plt.axhline(stats_mem['median'], linestyle='--', color='mediumseagreen', alpha=0.4, label='Med MEM')
    plt.axhline(stats_mem['Q1'], linestyle=':', color='navy', alpha=0.4, label='Q1 MEM')
    plt.axhline(stats_mem['Q3'], linestyle=':', color='navy', alpha=0.4, label='Q3 MEM')

    legend_stats = (
        f"CPU: Moy={stats_cpu['mean']:.1f}%, Med={stats_cpu['median']:.1f}%, "
        f"Q1={stats_cpu['Q1']:.1f}%, Q3={stats_cpu['Q3']:.1f}%\n"
        f"MEM: Moy={stats_mem['mean']:.1f}MB, Med={stats_mem['median']:.1f}MB, "
        f"Q1={stats_mem['Q1']:.1f}MB, Q3={stats_mem['Q3']:.1f}MB"
    )

    plt.title("Utilisation CPU et Mémoire (lissée)")
    plt.xlabel("Temps (s)")
    plt.ylabel("Utilisation")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.legend(loc='upper right')
    plt.figtext(0.5, 0.01, legend_stats, wrap=True, ha='center', fontsize=9)
    plt.tight_layout(rect=[0, 0.05, 1, 0.95])
    plt.savefig(output_file)
    plt.close()
    print(f"[OK] Graphique généré : {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tracer une courbe lissée depuis un log psrecord.")
    parser.add_argument("logfile", help="Fichier log psrecord, ex: logs/1234.txt")
    parser.add_argument("--window", type=int, default=5, help="Taille de la fenêtre de lissage (moyenne glissante)")
    parser.add_argument("--output", required=True, help="Chemin complet du fichier PNG de sortie")
    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        sys.exit(f"[ERREUR] Fichier introuvable : {args.logfile}")
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    t, cpu, mem = parse_psrecord_log(args.logfile)
    plot_smoothed_data(t, cpu, mem, args.window, args.output)
