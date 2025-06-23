#!/usr/bin/env python3
import sys
import os
import pandas as pd
import matplotlib.pyplot as plt

if len(sys.argv) != 3:
    print("Usage: draw-cpu-conso.py <csv_log_file> <output_dir>")
    sys.exit(1)

log_file = sys.argv[1]
output_dir = sys.argv[2]

if not os.path.exists(log_file):
    print(f"Log file not found: {log_file}")
    sys.exit(1)

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Lecture du CSV
df = pd.read_csv(log_file)

# Nettoyage : suppression lignes avec NaN ou PID incohérent
df = df.dropna()
df = df[df['PID'].apply(lambda x: str(x).isdigit())]  # garde que les vrais PIDs

# Conversion des types
df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
df['%CPU'] = pd.to_numeric(df['%CPU'], errors='coerce')
df['%MEM'] = pd.to_numeric(df['%MEM'], errors='coerce')
df['PID'] = df['PID'].astype(int)

# Recaler le temps en secondes depuis le début
df['Time (s)'] = df['Timestamp'] - df['Timestamp'].min()

# Tracer la conso CPU et MEM pour chaque PID
for pid in df['PID'].unique():
    df_pid = df[df['PID'] == pid]

    plt.figure(figsize=(10, 4))
    plt.plot(df_pid['Time (s)'], df_pid['%CPU'], label='CPU (%)')
    plt.plot(df_pid['Time (s)'], df_pid['%MEM'], label='MEM (%)')
    plt.title(f"Consommation CPU/MEM - PID {pid}")
    plt.xlabel("Temps (s)")
    plt.ylabel("Pourcentage (%)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()

    # Sauvegarde
    output_path = os.path.join(output_dir, f"pid_{pid}.png")
    plt.savefig(output_path)
    plt.close()

print(f"[OK] Graphes enregistrés dans : {output_dir}")
