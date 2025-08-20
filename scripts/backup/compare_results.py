import os
import sys
import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt


def compare(input_dir1, input_dir2, output, window, title1, title2):
	dir1 = Path(input_dir1)
	dir2 = Path(input_dir2)

	tiers_list = ["BE", "FE", "IS"]
	taille_list = ["16K", "32K", "64K", "128K", "256K"]
	metrics = ["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process"]
	stats_names = ["Min", "Max", "Moyenne", "Médianne","écart-type" "Q1", "Q3"]

	# Figure avec 3 subplots (espacés)
	fig, axes = plt.subplots(1, 3, figsize=(35, 12),constrained_layout=True)
	plt.subplots_adjust(wspace=0.5, bottom=0.15)  # plus d’espace entre tableaux et titre bas

	for i, tiers in enumerate(tiers_list):
		rows = []

		for taille in taille_list:
			f1 = dir1 / f"cpu_logs_{taille}_{tiers}.csv"
			f2 = dir2 / f"cpu_logs_{taille}_{tiers}.csv"

			if f1.exists() and f2.exists():
				df1 = pd.read_csv(f1)
				df2 = pd.read_csv(f2)

				for metric in metrics:
					if metric not in df1.columns or metric not in df2.columns:
						continue
					for stat in stats_names:
						if stat == "Min":
							v1, v2 = df1[metric].min(), df2[metric].min()
						elif stat == "Max":
							v1, v2 = df1[metric].max(), df2[metric].max()
						elif stat == "Moyenne":
							v1, v2 = df1[metric].mean(), df2[metric].mean()
						elif stat == "Médianne":
							v1, v2 = df1[metric].median(), df2[metric].median()
						elif stat == "écart-type":
							v1, v2 = df1[metric].std(), df2[metric].std()
						elif stat == "Q1":
							v1, v2 = df1[metric].quantile(0.25), df2[metric].quantile(0.25)
						elif stat == "Q3":
							v1, v2 = df1[metric].quantile(0.75), df2[metric].quantile(0.75)

						rows.append([taille, metric, stat, f"{v1:.2f}", f"{v2:.2f}"])

		if not rows:
			continue

		df_table = pd.DataFrame(rows, columns=["Taille", "Métrique", "Stat", title1, title2])

		# On insère une ligne d’en-tête supplémentaire avec le tiers
		header = pd.DataFrame([[f"Tiers {tiers}", "", "", "", ""]], columns=df_table.columns)
		df_table = pd.concat([header, df_table], ignore_index=True)

		# Affichage tableau
		axes[i].axis("off")
		table = axes[i].table(
			cellText=df_table.values,
			colLabels=df_table.columns,
			cellLoc="center",
			loc="center",
		)

		# Taille police
		table.auto_set_font_size(False)
		table.set_fontsize(8)
		table.scale(1, 1)

					
		# Mise en forme : couleurs alternées par taille et métrique
		nrows = len(df_table)
		for r in range(1,nrows): # on skip la ligne du tiers
			taille = df_table.iloc[r, 0]
			metric = df_table.iloc[r, 1]

			# Couleur de fond par taille
			if taille in ["16K", "64K", "256K"]:
				for c in range(len(df_table.columns)):
					table[(r + 1, c)].set_facecolor("#f2f2f2")

			# Couleur de fond par métrique
			if metric == "CPU_%_global":
				table[(r + 1, 1)].set_facecolor("#d9ead3")
			elif metric == "CPU_%_on_core":
				table[(r + 1, 1)].set_facecolor("#cfe2f3")
			elif metric == "CPU_%_by_process":
				table[(r + 1, 1)].set_facecolor("#fff2cc")

			# Mettre en rouge le max et bleu le min pour Dir1/Dir2
			vals = [float(df_table.iloc[r, 3]), float(df_table.iloc[r, 4])]
			min_val, max_val = min(vals), max(vals)
			for j in [3, 4]:
				if float(df_table.iloc[r, j]) == min_val:
					table[(r + 1, j)].set_text_props(color="blue", fontweight="bold")
				else:
					table[(r + 1, j)].set_text_props(color="red", fontweight="bold")
				

	#  Add an overall title to the figure
	fig.suptitle(f"Comparaison CPU entre {title1} et {title2}", fontsize=16)
	fig.tight_layout()
	fig.subplots_adjust(top=0.88)


	## Add top spacing for the suptitle
	#plt.subplots_adjust(top=0.9)
	plt.savefig(output)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Batch générateur de tableaux comparatifs CPU")
	parser.add_argument("input_dir1", help="Répertoire contenant les fichiers CSV de monitoring 1")
	parser.add_argument("input_dir2", help="Répertoire contenant les fichiers CSV de monitoring 2")
	parser.add_argument("output", help="Fichier PNG de sortie")
	parser.add_argument("--window", type=int, default=5, help="Taille de la fenêtre de lissage")
	parser.add_argument("--title1", type=str, default="Méthode 1", help="Nom de la méthode 1")
	parser.add_argument("--title2", type=str, default="Méthode 2", help="Nom de la méthode 2")
	args = parser.parse_args()

	if not os.path.exists(args.input_dir1) or not os.path.exists(args.input_dir2):
		sys.exit(f"[ERREUR] Répertoire introuvable")
  
	# On cree le repertoire de sortie s'il n'existe pas
	Path(args.output).parent.mkdir(parents=True, exist_ok=True)
 
	compare(args.input_dir1, args.input_dir2, args.output, args.window, args.title1, args.title2)
	print(f"\n[FIN] Graphique généré avec succès → {args.output}")


