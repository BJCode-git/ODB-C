import os
import sys
import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import plotly.graph_objects as go
import seaborn as sns

# ... import et parsing inchangés ...

def compare(input_dir1, input_dir2, output, title1, title2):
	dir1 = Path(input_dir1)
	dir2 = Path(input_dir2)

	tiers_list = ["BE", "FE", "IS"]
	taille_list = ["16K", "32K", "64K", "128K", "256K"]
	metrics = ["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process"]
	stats_names = ["Min", "Max", "Moyenne", "Médianne", "écart-type", "Q1", "Q3"]

	# Figure avec 3 subplots
	fig, axes = plt.subplots(1, 3, figsize=(35, 12), )
	plt.subplots_adjust(wspace=0.5, top=0.85)  # espace pour le titre global

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

		# On supprime la ligne “Tiers” et on utilise set_title pour l’axe
		axes[i].axis("off")
		axes[i].set_title(f"Tiers {tiers}", fontsize=14, pad=20)

		# Affichage tableau
		table = axes[i].table(
			cellText=df_table.values,
			colLabels=df_table.columns,
			cellLoc="center",
			loc="center",
		)

		table.auto_set_font_size(False)
		table.set_fontsize(8)
		table.scale(1, 1)

		# Couleurs alternées et mise en forme
		nrows = len(df_table)
		for r in range(nrows):
			taille = df_table.iloc[r, 0]
			metric = df_table.iloc[r, 1]

			# Couleur fond par taille
			if taille in ["16K", "64K", "256K"]:
				for c in range(len(df_table.columns)):
					table[(r, c)].set_facecolor("#f2f2f2")

			# Couleur fond par métrique
			if metric == "CPU_%_global":
				table[(r, 1)].set_facecolor("#d9ead3")
			elif metric == "CPU_%_on_core":
				table[(r, 1)].set_facecolor("#cfe2f3")
			elif metric == "CPU_%_by_process":
				table[(r, 1)].set_facecolor("#fff2cc")

			# Min en bleu, Max en rouge
			vals = [float(df_table.iloc[r, 3]), float(df_table.iloc[r, 4])]
			min_val, max_val = min(vals), max(vals)
			for j in [3, 4]:
				if float(df_table.iloc[r, j]) == min_val:
					table[(r, j)].set_text_props(color="blue", fontweight="bold")
				else:
					table[(r, j)].set_text_props(color="red", fontweight="bold")

	# Titre global
	fig.suptitle(f"Comparaison CPU entre {title1} et {title2}", fontsize=20, y=0.95)

	plt.savefig(output, bbox_inches='tight')
	plt.close()
	print(f"Comparaison CPU entre {title1} et {title2} enregistrée dans {output}")


def compare_plotly(input_dir1, input_dir2, output, title1, title2):
	dir1 = Path(input_dir1)
	dir2 = Path(input_dir2)

	tiers_list = ["BE", "FE", "IS"]
	taille_list = ["16K", "32K", "64K", "128K", "256K"]
	metrics = ["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process"]
	stats_names = ["Min", "Max", "Moyenne", "Médianne", "écart-type", "Q1", "Q3"]

	figs = []

	for tiers in tiers_list:
		rows = []
		for taille in taille_list:
			f1 = dir1 / f"cpu_logs_{taille}_{tiers}.csv"
			f2 = dir2 / f"cpu_logs_{taille}_{tiers}.csv"

			if not (f1.exists() and f2.exists()):
				continue

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

		# Mettre en couleur min/max
		colors = []
		for idx, row in df_table.iterrows():
			vals = [float(row[title1]), float(row[title2])]
			min_val, max_val = min(vals), max(vals)
			row_colors = []
			for v in vals:
				if v == min_val:
					row_colors.append("lightblue")
				elif v == max_val:
					row_colors.append("lightcoral")
				else:
					row_colors.append("white")
			colors.append(["white", "white", "white"] + row_colors)

		fig = go.Figure(data=[go.Table(
			header=dict(
				values=df_table.columns,
				fill_color='paleturquoise',
				align='center'
			),
			cells=dict(
				values=[df_table[col] for col in df_table.columns],
				fill_color=colors,
				align='center'
			)
		)])
		fig.update_layout(title_text=f"Tiers {tiers}", title_x=0.5)
		figs.append(fig)

	# Sauvegarde chaque tableau dans un fichier PNG séparé
	for i, fig in enumerate(figs):
		fig.write_image(f"{Path(output).stem}_{tiers_list[i]}.png")
	print(f"Tableaux générés avec succès → {output}")

def violin_box_comparison_values(input_dir1, input_dir2, output,
								 metrics=["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process"],
								 title1="Méthode 1", title2="Méthode 2"):
	dir1 = Path(input_dir1)
	dir2 = Path(input_dir2)

	tailles = ["16K", "32K", "64K", "128K", "256K"]
	tiers_list = ["FE", "IS", "BE"]

	sns.set_theme(style="whitegrid")
	fig, axes = plt.subplots(len(metrics), 
							 len(tiers_list),
							 figsize=(6*len(tiers_list), 
							 5*len(metrics)), 
							sharey=False)

	if len(metrics) == 1 and len(tiers_list) == 1:
		axes = [[axes]]
	elif len(metrics) == 1:
		axes = [axes]
	elif len(tiers_list) == 1:
		axes = [[ax] for ax in axes]

	for mi, metric in enumerate(metrics):
		all_data = []
		for tiers in tiers_list:
			for taille in tailles:
				f1 = dir1 / f"cpu_logs_{taille}_{tiers}.csv"
				f2 = dir2 / f"cpu_logs_{taille}_{tiers}.csv"

				if f1.exists():
					df1 = pd.read_csv(f1)
					if metric in df1.columns:
						all_data.append(pd.DataFrame({
							"Valeur": df1[metric],
							"Taille": taille,
							"Méthode": title1,
							"Tiers": tiers,
							"Taille_Methode": f"{taille}\n{title1}"  # clé X unique
						}))
				if f2.exists():
					df2 = pd.read_csv(f2)
					if metric in df2.columns:
						all_data.append(pd.DataFrame({
							"Valeur": df2[metric],
							"Taille": taille,
							"Méthode": title2,
							"Tiers": tiers,
							"Taille_Methode": f"{taille}\n{title2}"  # clé X unique
						}))
		if not all_data:
			continue

		df_all = pd.concat(all_data, ignore_index=True)

		for ti, tiers in enumerate(tiers_list):
			ax = axes[mi][ti]
			df_tiers = df_all[df_all["Tiers"] == tiers]
			#print("Tiers length :", str(len(df_tiers)))

			# Définir une palette fixe : méthode1 = bleu clair, méthode2 = orange clair
			palette = {f"{taille}\n{title1}": "skyblue" for taille in tailles}
			palette.update({f"{taille}\n{title2}": "lightcoral" for taille in tailles})

			sns.violinplot(
				x="Taille_Methode",
				y="Valeur",
				data=df_tiers,
				inner="box",
				palette=palette,   # <- palette dict
				width=0.8,         # violins plus fins
				ax=ax,
				legend=False       # <- plus de warning
			)

			# Groupement des labels X (on ne garde que la taille au 1er niveau)
			x_positions = [j + 0.5 for j in range(0, len(tailles)*2, 2)]
			ax.set_xticks(x_positions)
			ax.set_xticklabels(tailles)
			ax.set_title(f"{metric} - Tiers {tiers}", fontsize=12, y=1.25)

			# Hauteur fixe pour les textes
			y_pos = ax.get_ylim()[1] * 1.15
			# Afficher stats au-dessus / au centre de chaque violin
			for j, taille in enumerate(tailles):
				for k, method in enumerate([title1, title2]):
					vals = df_tiers[(df_tiers["Taille"] == taille) &
									(df_tiers["Méthode"] == method)]["Valeur"]
					#q = len(vals)
					#print(f"Taille des valeurs pour stats {q}")
					if vals.empty:
						continue
					stats = {
						"min": vals.min(),
						"max": vals.max(),
						"x": vals.mean(),
						"μ": vals.median(),
						"σ": vals.std(),
						"Q1": vals.quantile(0.25),
						"Q3": vals.quantile(0.75)
						
					}
					stats_text = "\n".join([f"{key}: {v:.1f}" for key, v in stats.items()])

					# Position X du violon
					xpos = j*2 + k  # méthode1=0, méthode2=1

					ax.text(xpos, y_pos, stats_text, ha='center', va='center', fontsize=6)


	# Patches pour les couleurs des méthodes
	method_patches = [
		mpatches.Patch(color="skyblue", label=title1),
		mpatches.Patch(color="lightcoral", label=title2)
	]

	# Patches pour les symboles statistiques (invisibles, juste pour la légende)
	stats_patches = [
		mpatches.Patch(color="white", label="x = moyenne"),
		mpatches.Patch(color="white", label="μ = médiane"),
		mpatches.Patch(color="white", label="σ = écart-type")
	]

	# On combine
	all_patches = method_patches + stats_patches

	fig.legend(handles=all_patches, loc="lower center", ncol=3, fontsize=10)

	plt.tight_layout(rect=[0, 0.05, 1, 0.95])
	plt.savefig(output, dpi=300)
	plt.close()
	print(f"Graphique PNG généré → {output}")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Batch générateur de tableaux comparatifs CPU")
	parser.add_argument("input_dir1", help="Répertoire contenant les fichiers CSV de monitoring 1")
	parser.add_argument("input_dir2", help="Répertoire contenant les fichiers CSV de monitoring 2")
	parser.add_argument("output", help="Fichier PNG de sortie")
	parser.add_argument("--title1", type=str, default="Méthode 1", help="Nom de la méthode 1")
	parser.add_argument("--title2", type=str, default="Méthode 2", help="Nom de la méthode 2")
	args = parser.parse_args()

	if not os.path.exists(args.input_dir1) or not os.path.exists(args.input_dir2):
		sys.exit(f"[ERREUR] Répertoire introuvable")
  
	# On cree le repertoire de sortie s'il n'existe pas
	Path(args.output).parent.mkdir(parents=True, exist_ok=True)
 
	#compare(args.input_dir1, args.input_dir2, args.output, args.title1, args.title2)
	violin_box_comparison_values(args.input_dir1, args.input_dir2, args.output, ["CPU_%_global", "CPU_%_on_core", "CPU_%_by_process"], args.title1, args.title2)
	

