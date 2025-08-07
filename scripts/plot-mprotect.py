import pandas as pd
import matplotlib.pyplot as plt
import sys

def plot_csv(filename, output_filename):
    # Lecture du CSV
    df = pd.read_csv(filename)

    # Vérifie les colonnes attendues
    expected_cols = {'type', 'allocated_size', 'user_time_usec', 'system_time_usec', 'total_time_usec'}
    if not expected_cols.issubset(df.columns):
        print("Erreur : colonnes manquantes dans le CSV")
        print("Colonnes trouvées :", df.columns.tolist())
        return

    # Forcer les colonnes numériques
    numeric_cols = ['allocated_size', 'user_time_usec', 'system_time_usec', 'total_time_usec']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.dropna(subset=numeric_cols, inplace=True)

    # Conversion µs → ms
    df['user_time_ms']   = df['user_time_usec'] / 1000.0
    df['system_time_ms'] = df['system_time_usec'] / 1000.0
    df['total_time_ms']  = df['total_time_usec'] / 1000.0

    # Séparation protection/unprotection
    prot    = df[df['type'] == 'protection']
    unprot  = df[df['type'] == 'unprotection']
    vanilla = df[df['type'] == 'vanilla']

    # Moyennes par taille allouée
    def group_avg(df):
        return df.groupby('allocated_size')[['user_time_ms', 'system_time_ms', 'total_time_ms']].mean().reset_index()

    prot_avg    = group_avg(prot)
    unprot_avg  = group_avg(unprot)
    vanilla_avg = group_avg(vanilla)
    
    # Total mprotection
    total_mprot = pd.merge(prot_avg, unprot_avg, on='allocated_size', suffixes=('_prot', '_unprot'))
    total_mprot['user_time_ms']   = total_mprot['user_time_ms_prot'] + total_mprot['user_time_ms_unprot']
    total_mprot['system_time_ms'] = total_mprot['system_time_ms_prot'] + total_mprot['system_time_ms_unprot']
    total_mprot['total_time_ms']  = total_mprot['total_time_ms_prot'] + total_mprot['total_time_ms_unprot']
    total_mprot['allocated_size'] = total_mprot['allocated_size']  # conserve la colonne d'origine

    # Tracé
     # Graphe principal : protection, unprotection, vanilla
    fig, axes = plt.subplots(2, 1, figsize=(14, 12), sharex=True)
    #plt.figure(figsize=(14, 7))
    ax = axes[0]

    # PROTECTION
    ax.plot(prot_avg['allocated_size'] / 1024, prot_avg['total_time_ms'],  label='Protection - total',  color='blue',   marker='o')
    ax.plot(prot_avg['allocated_size'] / 1024, prot_avg['user_time_ms'],   label='Protection - user',   color='blue',   linestyle='dotted')
    ax.plot(prot_avg['allocated_size'] / 1024, prot_avg['system_time_ms'], label='Protection - system', color='blue',   linestyle='dashed')

    # UNPROTECTION
    ax.plot(unprot_avg['allocated_size'] / 1024, unprot_avg['total_time_ms'],  label='Unprotection - total',  color='green', marker='s')
    ax.plot(unprot_avg['allocated_size'] / 1024, unprot_avg['user_time_ms'],   label='Unprotection - user',   color='green', linestyle='dotted')
    ax.plot(unprot_avg['allocated_size'] / 1024, unprot_avg['system_time_ms'], label='Unprotection - system', color='green', linestyle='dashed')
    
    # VANILLA 
    ax.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['total_time_ms'],  label='Vanilla - total',  color='red', marker='x')
    ax.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['user_time_ms'],   label='Vanilla - user',   color='red', linestyle='dotted')
    ax.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['system_time_ms'], label='Vanilla - system', color='red', linestyle='dashed')
    
    # Tracé
    ax.set_xlabel("Taille allouée (KB)")
    ax.set_ylabel("Temps (ms)")
    ax.set_title("Temps moyen de protection vs unprotection mémoire")
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend()

    # Graphe secondaire : vanilla vs (protection + unprotection)
    ax2 = axes[1]
    
    # Total mprotect
    ax2.plot(total_mprot['allocated_size'] / 1024, total_mprot['total_time_ms'],  label='Protection + Unprotection - total',  color='orange', marker='x')
    ax2.plot(total_mprot['allocated_size'] / 1024, total_mprot['user_time_ms'],   label='Protection + Unprotection - user',   color='orange', linestyle='dotted')
    ax2.plot(total_mprot['allocated_size'] / 1024, total_mprot['system_time_ms'], label='Protection + Unprotection - system', color='orange', linestyle='dashed')
    
    # Vanilla
    ax2.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['total_time_ms'],  label='Vanilla - total',  color='red', marker='x')
    ax2.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['user_time_ms'],   label='Vanilla - user',   color='red', linestyle='dotted')
    ax2.plot(vanilla_avg['allocated_size'] / 1024, vanilla_avg['system_time_ms'], label='Vanilla - system', color='red', linestyle='dashed')
    
    # Tracé
    ax2.set_xlabel("Taille allouée (KB)")
    ax2.set_ylabel("Temps (ms)")
    ax2.set_title("Temps moyen de mprotect vs vanilla")
    ax2.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax2.legend()

    # Sauvegarde
    
    plt.suptitle("Comparaison de temps moyen d'écriture d'un bit avec protection et sans protection")
    plt.tight_layout()
    plt.savefig(output_filename)
    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python plot_memory_timings.py resultats.csv output.png")
        sys.exit(1)

    plot_csv(sys.argv[1], sys.argv[2])
    sys.exit(0)