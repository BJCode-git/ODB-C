import os
import sys
import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns


def draw_qos_cmp(input_dir1, input_dir2, mode1, mode2, output,
                 title1="Méthode 1", title2="Méthode 2"):

    dir1 = Path(input_dir1)
    dir2 = Path(input_dir2)

    tailles = ["16K", "32K", "64K", "128K", "256K"]
    metrics = ["Median Response Time","Average Response Time","Min Response Time","Max Response Time"]    

    cmp1_dict = {metric: [] for metric in metrics}
    cmp2_dict = {metric: [] for metric in metrics}

    for taille in tailles:
        f1 = dir1 / f"{taille}/{mode1}/locust-LOC/results_stats.csv"
        f2 = dir2 / f"{taille}/{mode2}/locust-LOC/results_stats.csv"

        if f1.exists():
            df1 = pd.read_csv(f1)
            row1 = df1.iloc[0]
            for metric in metrics:
                cmp1_dict[metric].append(row1[metric])
        else:
            for metric in metrics:
                cmp1_dict[metric].append(None)

        if f2.exists():
            df2 = pd.read_csv(f2)
            row2 = df2.iloc[0]
            for metric in metrics:
                cmp2_dict[metric].append(row2[metric])
        else:
            for metric in metrics:
                cmp2_dict[metric].append(None)

    # Création du DataFrame fusionné
    data = []
    for metric in metrics:
        for i, taille in enumerate(tailles):
            data.append({"Taille de la payload": taille, "Méthode": title1, "Métrique": metric, "Latence(ms)": cmp1_dict[metric][i]})
            data.append({"Taille de la payload": taille, "Méthode": title2, "Métrique": metric, "Latence(ms)": cmp2_dict[metric][i]})
    df_plot = pd.DataFrame(data)


    # Histogrammes groupés
    g = sns.catplot(
        data=df_plot, kind="bar",
        x="Taille de la payload", y="Latence(ms)", 
        hue="Méthode",
        col="Métrique", col_wrap=2,
        height=4, aspect=1.2,
        sharey=False   # ✅ échelles indépendantes
    )

    g.set_titles("{col_name}",y=1.10)
    g.set_axis_labels("Taille de la payload", "Latence(ms)")
    g._legend.set_title("Méthode")
    g._legend.set_loc("lower center")
    
    # Ajouter les valeurs au-dessus de chaque barre
    for ax in g.axes.flat:
        for c in ax.containers:
            ax.bar_label(c, fmt="%.2f", label_type="edge", fontsize=8, rotation=90, padding=2)

    plt.subplots_adjust(top=0.85,bottom=0.15,hspace=0.35)
    g.figure.suptitle("Comparaison QoS entre les méthodes")

    plt.savefig(output)
    plt.close()
    print(f"\nGraphique généré avec succès → {output}")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Batch générateur de tableaux comparatifs CPU")
	parser.add_argument("input_dir1", help="Répertoire contenant les fichiers CSV de monitoring 1")
	parser.add_argument("mode1", help="Mode 1 (odb ou vanilla)")
	parser.add_argument("input_dir2", help="Répertoire contenant les fichiers CSV de monitoring 2")
	parser.add_argument("mode2", help="Mode 2 (odb ou vanilla)")
	parser.add_argument("output", help="Fichier PNG de sortie")
	parser.add_argument("--title1", type=str, default="Méthode 1", help="Nom de la méthode 1")
	parser.add_argument("--title2", type=str, default="Méthode 2", help="Nom de la méthode 2")
	args = parser.parse_args()

	if not os.path.exists(args.input_dir1) or not os.path.exists(args.input_dir2):
		sys.exit(f"[ERREUR] Répertoire introuvable")
  
	# On cree le repertoire de sortie s'il n'existe pas
	Path(args.output).parent.mkdir(parents=True, exist_ok=True)
 
	draw_qos_cmp(args.input_dir1, args.input_dir2, args.mode1, args.mode2, args.output, args.title1, args.title2)
	

