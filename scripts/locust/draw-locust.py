import pandas as pd
import matplotlib.pyplot as plt
from sys import argv, exit
import os
import re

def sanitize_filename(filename):
	# Remplacer les caractères spéciaux par des underscores
	return re.sub(r'[\\/*?:"<>|]', '_', filename)

def draw_results(results_dir, output_dir):
	# Créer le répertoire de sortie s'il n'existe pas
	os.makedirs(output_dir, exist_ok=True)

	# Chemin vers les fichiers CSV
	csv_files = {
		"exceptions": os.path.join(results_dir, "results_exceptions.csv"),
		"failures": os.path.join(results_dir, "results_failures.csv"),
		"stats": os.path.join(results_dir, "results_stats.csv"),
		"stats_history": os.path.join(results_dir, "results_stats_history.csv")
	}

	# Lire les fichiers CSV
	data = {}
	for key, file in csv_files.items():
		if os.path.exists(file):
			data[key] = pd.read_csv(file)
		else:
			print(f"File {file} not found.")

	# Tracer les graphiques pour chaque type de fichier
	if "exceptions" in data and not data["exceptions"].empty:
		df = data["exceptions"]
		os.makedirs(output_dir+'/exceptions', exist_ok=True)
		for column in df.columns:
			if column != 'Count':
				plt.figure(figsize=(10, 6))
				plt.plot(df['Count'], df[column])
				plt.xlabel('Count')
				plt.ylabel(column)
				plt.title(f'{column} Over Count')
				plt.savefig(os.path.join(output_dir, f'exceptions/{sanitize_filename(column)}.png'))
				plt.close()

	if "failures" in data and not data["failures"].empty:
		df = data["failures"]
		os.makedirs(output_dir+'/failures', exist_ok=True)
		for column in df.columns:
			if column != 'Occurrences':
				plt.figure(figsize=(10, 6))
				plt.plot(df['Occurrences'], df[column])
				plt.xlabel('Occurrences')
				plt.ylabel(column)
				plt.title(f'{column} Over Occurrences')
				plt.savefig(os.path.join(output_dir, f'failures/{sanitize_filename(column)}.png'))
				plt.close()

	if "stats_history" in data and not data["stats_history"].empty:
		df = data["stats_history"]
		os.makedirs(output_dir+'/stats_history', exist_ok=True)
		for column in df.columns:
			if column != 'Timestamp':
				plt.figure(figsize=(10, 6))
				plt.plot(df['Timestamp'], df[column])
				plt.xlabel('Timestamp')
				plt.ylabel(column)
				plt.title(f'{column} Over Time')
				plt.savefig(os.path.join(output_dir, f'stats_history/{sanitize_filename(column)}.png'))
				plt.close()

	if "stats" in data and not data["stats"].empty:
		df = data["stats"]
		os.makedirs(output_dir+'/stats', exist_ok=True)
		for column in df.columns:
			if column != 'Type' and column != 'Name':
				plt.figure(figsize=(10, 6))
				plt.bar(df['Name'], df[column])
				plt.xlabel('Name')
				plt.ylabel(column)
				plt.title(f'{column} by Name')
				plt.xticks(rotation=45)
				plt.savefig(os.path.join(output_dir, f'stats/{sanitize_filename(column)}.png'), bbox_inches='tight')
				plt.close()

	print(f"Graphs have been generated and saved as PNG files in {output_dir}.")

if __name__ == '__main__':
	# get argument from command line
	if len(argv) != 3:
		print("Usage: python3 draw-locust.py <results_directory> <graphs_output_directory>")
		exit(1)

	draw_results(argv[1], argv[2])
