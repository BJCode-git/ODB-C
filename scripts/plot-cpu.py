import os
import sys
import argparse
from pathlib import Path
import traceback

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from statistics import mean, median, quantiles


def moving_average(data, window_size):
    if window_size < 2 or len(data) < window_size:
        return np.array(data)
    return np.convolve(data, np.ones(window_size) / window_size, mode='valid')


def describe(data):
    return {
        "mean": mean(data),
        "median": median(data),
        "Q1": quantiles(data, n=4)[0],
        "Q3": quantiles(data, n=4)[2],
    }


def plot_with_stats(time, series_dict, window, ax, title, ylabel):
    stat_lines = []

    for label, data in series_dict.items():
        smoothed = moving_average(data, window)
        smoothed_time = time[:len(smoothed)]
        stats = describe(data)

        ax.plot(smoothed_time, smoothed, label=label)
        stat_lines.append((f"{label} Moyenne", stats['mean'], '--'))
        stat_lines.append((f"{label} Médiane", stats['median'], '--'))
        stat_lines.append((f"{label} Q1", stats['Q1'], ':'))
        stat_lines.append((f"{label} Q3", stats['Q3'], ':'))

    for label, yval, style in stat_lines:
        ax.axhline(yval, linestyle=style, alpha=0.3, label=f"{label} ({yval:.1f})")

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=7)
    ax.grid(True, linestyle="--", alpha=0.5)


def compute_rate(series, time):
    delta_vals = np.diff(series, prepend=series[0])
    delta_time = np.diff(time, prepend=time[0])
    with np.errstate(divide='ignore', invalid='ignore'):
        rate = np.where(delta_time > 0, delta_vals / delta_time, 0)
    return rate


def enrich_pid_cpu_with_core_data(df):
    cpu_pid_cols = [c for c in df.columns if c.startswith("CPU_") and not c.endswith("_io") and not c.startswith("CPU_percent_core_pin") and c != "Total_CPU_percent"]
    core_pin_cols = [c for c in df.columns if c.startswith("CPU_percent_core_pin")]

    cores = set()
    for col in core_pin_cols:
        parts = col.split('_')
        if parts[-1].isdigit():
            cores.add(int(parts[-1]))

    for core_num in cores:
        core_col_name = f"CPU_Core_{core_num}"
        if core_col_name in df.columns:
            df[f"CPU_core_{core_num}"] = df[core_col_name]


def plot_multiple_subplots(time, series_list, window, output_file, main_title):
    """
    series_list : list de tuples (dict_series, title, ylabel)
      - dict_series : dict label -> array données
      - title : titre du subplot
      - ylabel : label axe y
    """
    n = len(series_list)
    fig, axs = plt.subplots(n, 1, figsize=(14, 5 * n), sharex=True)
    if n == 1:
        axs = [axs]

    for ax, (series_dict, title, ylabel) in zip(axs, series_list):
        plot_with_stats(time, series_dict, window, ax, title, ylabel)

    axs[-1].set_xlabel("Temps (s)")
    fig.suptitle(main_title)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(output_file)
    plt.close()
    print(f"[OK] Graphique généré : {output_file}")


def plot_from_csv(logfile, graph_type, window, output_file):
    df = pd.read_csv(logfile)

    if 'time' not in df.columns:
        df['time'] = np.arange(len(df))

    time = df['time'].values

    if graph_type == 'cpu_sys':
        # Nouveau comportement : 2 sous-graphes, un pour CPU, un pour mémoire
        series_list = [
            ({"CPU total (%)": df["Total_CPU_percent"].values}, "Utilisation CPU Système", "Pourcentage (%)"),
            ({"Mémoire utilisée (%)": df["Total_Memory_percent"].values}, "Utilisation Mémoire Système", "Pourcentage (%)"),
        ]
        plot_multiple_subplots(time, series_list, window, output_file, "Utilisation CPU et Mémoire Système")

    elif graph_type == 'cpu_pids':
        # Gestion des PID avec sous-graphes pour :
        # CPU_%_global, CPU_%_on_core, CPU_percent_core_pin, Memory_%
        # On suppose que le fichier contient ces colonnes (ou on gère si absentes)

        cols_global = [c for c in df.columns if "CPU_%_global" in c]
        cols_on_core = [c for c in df.columns if "CPU_%_on_core" in c]
        cols_core_pin = [c for c in df.columns if "CPU_percent_core_pin" in c]
        cols_mem = [c for c in df.columns if "Memory_%" in c]

        series_list = []

        if cols_global:
            series_global = {c: df[c].values for c in cols_global}
            series_list.append((series_global, "CPU % Global par PID", "CPU (%)"))

        if cols_on_core:
            series_on_core = {c: df[c].values for c in cols_on_core}
            series_list.append((series_on_core, "CPU % on Core par PID", "CPU (%)"))

        if cols_core_pin:
            series_core_pin = {c: df[c].values for c in cols_core_pin}
            series_list.append((series_core_pin, "CPU Percent Core Pin par PID", "CPU (%)"))

        if cols_mem:
            series_mem = {c: df[c].values for c in cols_mem}
            series_list.append((series_mem, "Mémoire % par PID", "Mémoire (%)"))

        if not series_list:
            raise ValueError("Aucune colonne CPU_%_global, CPU_%_on_core, CPU_percent_core_pin, ni Memory_% trouvée dans le fichier.")

        plot_multiple_subplots(time, series_list, window, output_file, "Utilisation CPU et Mémoire par PID")

    elif graph_type == 'sys_network':
        if not {'Bytes_sent', 'Bytes_received'}.issubset(df.columns):
            raise ValueError("Colonnes Bytes_sent et Bytes_received absentes.")
        rate_sent = compute_rate(df['Bytes_sent'].values, time)
        rate_recv = compute_rate(df['Bytes_received'].values, time)
        series = {
            "Débit envoi (octets/s)": rate_sent,
            "Débit réception (octets/s)": rate_recv
        }
        plot_with_stats(time, series, window, plt.gca(), "Débit Réseau Système", "Octets/s")
        plt.gcf().savefig(output_file)
        plt.close()
        print(f"[OK] Graphique généré : {output_file}")

    elif graph_type == 'pid_network':
        read_cols = [c for c in df.columns if c.endswith('_read_bytes')]
        write_cols = [c for c in df.columns if c.endswith('_write_bytes')]
        if not read_cols and not write_cols:
            raise ValueError("Aucune colonne IO par PID trouvée dans le fichier.")
        series = {}
        for col in read_cols:
            series[f"{col} (lecture)"] = compute_rate(df[col].values, time)
        for col in write_cols:
            series[f"{col} (écriture)"] = compute_rate(df[col].values, time)
        plot_with_stats(time, series, window, plt.gca(), "I/O disque par PID (octets/s)", "Octets/s")
        plt.gcf().savefig(output_file)
        plt.close()
        print(f"[OK] Graphique généré : {output_file}")

    else:
        raise ValueError(f"Type de graphe non reconnu : {graph_type}")


def main(input_dir, output_dir, window):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    graph_types = ['cpu_sys', 'cpu_pids', 'sys_network', 'pid_network']

    csv_files = list(input_path.glob("*.csv"))
    if not csv_files:
        print(f"[ERREUR] Aucun fichier CSV trouvé dans {input_dir}")
        return

    success_count = 0
    fail_count = 0

    for csv_file in csv_files:
        print(f"\nTraitement de : {csv_file.name}")
        base_name = csv_file.stem
        csv_output_dir = output_path / base_name
        csv_output_dir.mkdir(exist_ok=True)

        for gtype in graph_types:
            out_png = csv_output_dir / f"{base_name}_{gtype}.png"
            try:
                plot_from_csv(csv_file, gtype, window, str(out_png))
                success_count += 1
            except Exception as e:
                print(f"[ERREUR] Impossible de générer {gtype} pour {csv_file.name} : {e}")
                fail_count += 1

    print(f"\n[FIN] Graphiques générés avec succès : {success_count}")
    print(f"[FIN] Graphiques échoués : {fail_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch générateur de graphes à partir de CSV de monitoring")
    parser.add_argument("input_dir", help="Répertoire contenant les fichiers CSV de monitoring")
    parser.add_argument("output_dir", help="Répertoire où seront enregistrés les graphes PNG")
    parser.add_argument("--window", type=int, default=5, help="Taille de la fenêtre de lissage (moyenne glissante)")
    args = parser.parse_args()

    if not os.path.exists(args.input_dir):
        sys.exit(f"[ERREUR] Répertoire introuvable : {args.input_dir}")

    main(args.input_dir, args.output_dir, args.window)
